import logging
import typing
from datetime import datetime as dt
from datetime import timezone as tz
from typing import Any

import httpx
import truststore
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import (
  ECDSA,
  EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate
from cryptography.x509.ocsp import (
  OCSPCertStatus,
  OCSPRequest,
  OCSPRequestBuilder,
  OCSPResponse,
  OCSPResponseStatus,
  load_der_ocsp_response,
)
from cryptography.x509.oid import (
  AuthorityInformationAccessOID,
  ExtendedKeyUsageOID,
)
from lxml import etree

from . import (
  _ALLOWED_HASH_ALGORITHMS,
  _CLOCK_SKEW,
  _MAX_RESPONSE_AGE,
)
from .ErrorTypes import CAPRevocationError
from .types import (
  PipelineState,
  ValidationContext,
  ValidationStep,
)

logger = logging.getLogger(__name__)


def _default_http_client(timeout_seconds: float) -> httpx.Client:
  """Build an ``httpx.Client`` for OCSP/CRL fetches, preferring the
  system trust store for the *transport* TLS connection itself (distinct
  from the CAP-signer trust decision made in ``TrustChainStep``).
  """
  verify: typing.Any = True
  if truststore is not None:
    import ssl

    verify = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
  return httpx.Client(timeout=timeout_seconds, verify=verify)


class RevocationStep(ValidationStep):
  """Checks the signer certificate's revocation status via OCSP
  (preferred) and falls back to CRL if no OCSP responder is advertised
  or reachable.

  Behavior is governed by ``ValidationContext.require_ocsp_crl``:

  * ``True``: revocation status MUST be affirmatively resolved to
    "good". Any responder failure, timeout, or "unknown" status is a
    hard :class:`CAPRevocationError`.
  * ``False`` (default): a confirmed "revoked" status is always a hard
    failure; anything else (unreachable responder, no AIA/CDP extension
    present, indeterminate status) is logged and treated as passing,
    since best-effort revocation checking should not brick validation of
    an otherwise-valid, time-sensitive emergency alert due to transient
    network issues.
  """

  __slots__ = ("_http_client_factory",)

  def __init__(
    self,
    http_client_factory: typing.Callable[[float], httpx.Client] | None = None,
  ) -> None:
    self._http_client_factory = http_client_factory or _default_http_client

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> None:
    if state is None:
      state = PipelineState()
    if state.signer_certificate is None:
      raise CAPRevocationError(
        "RevocationStep ran without a signer certificate; "
        "CryptoSignatureStep must run first"
      )

    cert = state.signer_certificate
    issuer = self._resolve_issuer(cert, context)

    status, detail = self._check_ocsp(cert, issuer, context)
    if status is None:
      status, detail = self._check_crl(cert, context)

    if status == OCSPCertStatus.REVOKED:
      raise CAPRevocationError(f"Signer certificate is revoked: {detail}")

    if status is None and context.require_ocsp_crl:
      raise CAPRevocationError(
        f"Revocation status could not be determined via OCSP or CRL, "
        f"and require_ocsp_crl=True: {detail}"
      )

    if status is None:
      logger.info(
        "Revocation status unresolved for certificate serial=%s (%s); "
        "proceeding because require_ocsp_crl=False",
        cert.serial_number,
        detail,
      )

  # -- issuer resolution -------------------------------------------------

  @staticmethod
  def _resolve_issuer(
    cert: x509.Certificate, context: ValidationContext
  ) -> x509.Certificate | None:
    """Find the issuer certificate among the trusted anchors, needed to
    build an OCSP request and to verify the OCSP response signature.
    """
    for anchor in context.resolved_trusted_certs():
      if anchor.subject == cert.issuer:
        return anchor
    return None

  # -- OCSP ---------------------------------------------------------------

  def _check_ocsp(
    self,
    cert: x509.Certificate,
    issuer: x509.Certificate | None,
    context: ValidationContext,
  ) -> tuple[OCSPCertStatus | None, str]:
    if issuer is None:
      return None, "issuer certificate not available; cannot build OCSP request"

    try:
      aia_ext = cert.extensions.get_extension_for_class(
        x509.AuthorityInformationAccess
      )
      ocsp_urls = [
        desc.access_location.value
        for desc in aia_ext.value
        if desc.access_method == AuthorityInformationAccessOID.OCSP
      ]
    except x509.ExtensionNotFound:
      return (
        None,
        "certificate has no Authority Information Access (OCSP) extension",
      )

    if not ocsp_urls:
      return None, "AIA extension present but contains no OCSP responder URL"

    builder: OCSPRequestBuilder = OCSPRequestBuilder().add_certificate(
      cert, issuer, hashes.SHA256()
    )
    request: OCSPRequest = builder.build()
    request_der: bytes = request.public_bytes(encoding=Encoding.DER)

    last_error = "no OCSP responders reachable"
    with self._http_client_factory(context.http_timeout_seconds) as client:
      for url in ocsp_urls:
        try:
          response = client.post(
            url,
            content=request_der,
            headers={"Content-Type": "application/ocsp-request"},
          )
          response.raise_for_status()
          ocsp_response = load_der_ocsp_response(response.content)
        except (httpx.HTTPError, ValueError) as exc:
          last_error = f"OCSP request to {url} failed: {exc}"
          continue

        if ocsp_response.response_status != OCSPResponseStatus.SUCCESSFUL:
          last_error = f"OCSP responder {url} returned status {ocsp_response.response_status}"
          continue

        if not self._verify_ocsp_response_signature(ocsp_response, issuer):
          last_error = (
            f"OCSP response from {url} has an invalid or untrusted signature"
          )
          continue

        # RFC 6960 4.2.1: match the FULL CertID (hash alg, issuer name
        # hash, issuer key hash, serial number) against what we asked
        # for -- serial number alone is only unique per-issuer, not
        # globally, so this is required, not just belt-and-braces.
        if (
          ocsp_response.hash_algorithm.name != request.hash_algorithm.name
          or ocsp_response.issuer_name_hash != request.issuer_name_hash
          or ocsp_response.issuer_key_hash != request.issuer_key_hash
          or ocsp_response.serial_number != request.serial_number
        ):
          last_error = (
            f"OCSP response from {url} does not match the requested "
            f"certificate (CertID mismatch)"
          )
          continue

        now = context.effective_verification_time
        this_update = ocsp_response.this_update_utc
        next_update = ocsp_response.next_update_utc

        # A response claiming to be produced in the future (beyond
        # reasonable clock skew) cannot be trusted as current.
        if this_update is not None and this_update > now + _CLOCK_SKEW:
          last_error = (
            f"OCSP response from {url} has a thisUpdate in the future "
            f"({this_update})"
          )
          continue

        # A stale response (thisUpdate far in the past, or past
        # nextUpdate) must not be trusted as current status.
        if next_update is not None:
          if now > next_update:
            last_error = (
              f"OCSP response from {url} is stale (nextUpdate={next_update})"
            )
            continue
        elif this_update is not None and now - this_update > _MAX_RESPONSE_AGE:
          # RFC 6960 2.4: nextUpdate absent means the responder makes
          # no claim about freshness -- the client must apply its own
          # staleness policy rather than trust the response forever.
          last_error = (
            f"OCSP response from {url} has no nextUpdate and is older "
            f"than the local staleness limit (thisUpdate={this_update})"
          )
          continue

        return ocsp_response.certificate_status, f"OCSP responder {url}"

    return None, last_error

  @staticmethod
  def _verify_ocsp_response_signature(
    ocsp_response: OCSPResponse, issuer: Certificate
  ) -> bool:
    """Verify the OCSP response was signed by the issuer (or an OCSP
    signing delegate certified by the issuer).
    """
    signer_cert: Certificate = (
      ocsp_response.certificates[0] if ocsp_response.certificates else issuer
    )

    if signer_cert is not issuer:
      try:
        # Signature + name-matching only; does NOT check validity
        # period, EKU, or revocation -- those are checked explicitly
        # below.
        signer_cert.verify_directly_issued_by(issuer)

        now = dt.now(tz.utc)
        if not (
          signer_cert.not_valid_before_utc
          <= now
          <= signer_cert.not_valid_after_utc
        ):
          logger.debug("OCSP delegate certificate is expired or not yet valid")
          return False

        # RFC 6960 4.2.2.2: a delegate signer MUST be authorized via
        # the id-kp-OCSPSigning EKU.
        try:
          eku = signer_cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
          ).value
        except x509.ExtensionNotFound:
          logger.debug("OCSP delegate certificate has no EKU extension")
          return False

        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
          logger.debug(
            "OCSP delegate certificate is not authorized for OCSP signing"
          )
          return False
      except Exception:  # noqa: BLE001
        logger.debug(
          "OCSP delegate certificate validation failed", exc_info=True
        )
        return False

    try:
      public_key = signer_cert.public_key()

      hash_alg: HashAlgorithm | None = ocsp_response.signature_hash_algorithm
      if hash_alg is None or not isinstance(hash_alg, _ALLOWED_HASH_ALGORITHMS):
        logger.debug("OCSP response uses disallowed or missing hash algorithm")
        return False

      if isinstance(public_key, RSAPublicKey):
        public_key.verify(
          ocsp_response.signature,
          ocsp_response.tbs_response_bytes,
          PKCS1v15(),
          hash_alg,
        )
      elif isinstance(public_key, EllipticCurvePublicKey):
        public_key.verify(
          ocsp_response.signature,
          ocsp_response.tbs_response_bytes,
          ECDSA(hash_alg),
        )
      else:
        logger.debug(
          "OCSP signer public key type not supported: %s", type(public_key)
        )
        return False

      return True
    except Exception:  # noqa: BLE001
      logger.debug("OCSP response signature verification failed", exc_info=True)
      return False

  # -- CRL fallback --------------------------------------------------------

  def _check_crl(
    self, cert: x509.Certificate, context: ValidationContext
  ) -> tuple[OCSPCertStatus | None, str]:
    try:
      cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
      return None, "certificate has no CRL Distribution Points extension"

    urls: list[str] = []
    for point in cdp.value:
      if point.full_name:
        urls.extend(
          name.value
          for name in point.full_name
          if isinstance(name, x509.UniformResourceIdentifier)
        )
    if not urls:
      return None, "CDP extension present but contains no HTTP(S) URLs"

    last_error = "no CRL distribution points reachable"
    with self._http_client_factory(context.http_timeout_seconds) as client:
      for url in urls:
        try:
          response = client.get(url)
          response.raise_for_status()
          crl = x509.load_der_x509_crl(response.content)
        except (httpx.HTTPError, ValueError) as exc:
          last_error = f"CRL fetch from {url} failed: {exc}"
          continue

        next_update = crl.next_update_utc
        now = context.effective_verification_time
        if next_update is not None and now > next_update:
          last_error = f"CRL from {url} is stale (nextUpdate={next_update})"
          continue

        revoked = crl.get_revoked_certificate_by_serial_number(
          cert.serial_number
        )
        if revoked is not None:
          return (
            OCSPCertStatus.REVOKED,
            f"CRL {url}, revoked at {revoked.revocation_date_utc}",
          )
        return OCSPCertStatus.GOOD, f"CRL {url}"

    return None, last_error
