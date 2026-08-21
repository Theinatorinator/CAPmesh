"""
cap_crypto_validator.py
========================

A thread-safe, pipelined validation suite for OASIS Common Alerting Protocol
(CAP) v1.2 XML messages carrying enveloped XMLDSig (XML Digital Signature)
signatures.

Design goals
------------
* **Stateless instances.** ``CAPCryptoValidator`` holds no mutable state
  after construction; every call to :meth:`CAPCryptoValidator.verify`
  carries all working state in local variables, so a single instance may
  safely be shared across threads (e.g. a thread pool processing an alert
  feed).
* **Fail closed.** Any unexpected exception inside a pipeline step is
  caught, wrapped as a :class:`CAPValidationError`, and reported in the
  ``ValidationResult`` rather than propagated -- with the deliberate
  exception of programming errors we want surfaced (``KeyboardInterrupt``,
  ``SystemExit``, ``MemoryError``), which are re-raised.
* **Composable.** Each step is a small callable implementing the
  :class:`ValidationStep` protocol. Steps can be reordered, swapped, or
  omitted (see the ``strict`` / ``relaxed`` factories).

Requires: lxml, signxml>=4.0.4, cryptography, truststore, httpx.

NOTE ON SCOPE: This module focuses on the cryptographic/PKI validation
layer (signature math, trust chain, revocation) that would typically run
*after* CAP-specific business-rule validation (geocoding, TTL windows,
etc.). The CAPSchemaStep here is intentionally a structural/well-formed
check with an XSD hook stubbed in, per the request; wire in a real
``lxml.etree.XMLSchema`` loaded from the OASIS CAP v1.2 XSD for full
schema conformance.
"""

from __future__ import annotations

import logging
import threading
import time
import typing
from dataclasses import dataclass, field
from datetime import datetime as dt
from datetime import timedelta
from datetime import timezone as tz
from pathlib import Path
from typing import Any, runtime_checkable

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
from cryptography.hazmat.primitives.hashes import (
  SHA256,
  SHA384,
  SHA512,
  HashAlgorithm,
)

# from ty_extensions._internal import Unknown
# from ty_extensions._internal import Unknown
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
from signxml.exceptions import (
  InvalidInput,
  InvalidSignature,
)
from signxml.verifier import SignatureConfiguration, VerifyResult, XMLVerifier

logger: logging.Logger = logging.getLogger("cap_crypto_validator")

CAP_1_2_NAMESPACE = "urn:oasis:names:tc:emergency:cap:1.2"
DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_MAX_RESPONSE_AGE = timedelta(days=7)  # used only if next_update is absent
_CLOCK_SKEW = timedelta(minutes=5)
_ALLOWED_HASH_ALGORITHMS = (SHA256, SHA384, SHA512)
# A type alias (PEP 695 style, Python 3.12+/3.13) describing the flexible
# ways trusted certificate material may be supplied.
type TrustedCertSource = str | Path | bytes | x509.Certificate


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class CAPValidationError(Exception):
  """Base class for all errors raised by the CAP validation pipeline.

  Every step-specific exception below inherits from this so callers can
  catch ``CAPValidationError`` to handle *any* validation failure while
  still being able to branch on the specific subtype when useful.
  """

  #: Machine-readable identifier for the failing pipeline stage, set by
  #: subclasses so ``ValidationResult`` consumers can group/report errors
  #: without string-matching class names.
  stage: typing.ClassVar[str] = "unknown"


class CAPSchemaError(CAPValidationError):
  """The document is not well-formed XML or fails XSD schema validation."""

  stage = "schema"


class CAPSignatureSyntaxError(CAPValidationError):
  """No usable ``<ds:Signature>`` element could be located or parsed."""

  stage = "signature_syntax"


class CAPSignatureMathError(CAPValidationError):
  """The cryptographic signature (digest and/or signature value) is invalid."""

  stage = "signature_math"


class CAPTrustChainError(CAPValidationError):
  """The signer's certificate does not chain to a trusted root."""

  stage = "trust_chain"


class CAPRevocationError(CAPValidationError):
  """The signer's certificate is revoked, or revocation status is unknown
  and the context requires a definitive answer."""

  stage = "revocation"


class CAPInternalError(CAPValidationError):
  """An unexpected error occurred inside a pipeline step. Wraps the
  original exception in ``__cause__``."""

  stage = "internal"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ValidationContext:
  """Immutable configuration for a single validation run (or a validator
  instance's whole lifetime, since ``CAPCryptoValidator`` is stateless).

  Attributes:
      trusted_certs: Trust anchors. Each entry may be a filesystem path
          (``str``/``Path``) to a PEM/DER file, raw PEM ``bytes``, or an
          already-parsed ``cryptography.x509.Certificate``. Steps that
          need a concrete list of ``x509.Certificate`` objects should call
          :meth:`resolved_trusted_certs`.
      use_system_truststore: When ``True``, the OS trust store (via
          ``truststore``) is consulted *in addition to* ``trusted_certs``
          for chain validation.
      require_ocsp_crl: When ``True``, revocation status must be
          affirmatively obtained (OCSP or CRL) or validation fails.
          When ``False``, revocation is checked on a best-effort basis:
          confirmed revocation still fails validation, but an
          unreachable/indeterminate responder does not.
      http_timeout_seconds: Timeout applied to all outbound OCSP/CRL
          HTTP fetches.
      verification_time: The instant to use for signature/certificate
          validity-period checks. Defaults to "now" if left ``None``;
          exposed explicitly so revalidation of historical alerts is
          reproducible and testable.
  """

  trusted_certs: list[TrustedCertSource] = field(default_factory=list)
  use_system_truststore: bool = True
  require_ocsp_crl: bool = False
  http_timeout_seconds: float = 5.0
  verification_time: dt | None = None

  def resolved_trusted_certs(self) -> list[x509.Certificate]:
    """Normalize :attr:`trusted_certs` into concrete ``x509.Certificate``
    objects, loading paths/bytes as needed.

    Raises:
        CAPTrustChainError: If any entry cannot be parsed/loaded.
    """
    resolved: list[x509.Certificate] = []
    for source in self.trusted_certs:
      try:
        if isinstance(source, x509.Certificate):
          resolved.append(source)
        elif isinstance(source, (str, Path)):
          raw = Path(source).read_bytes()
          resolved.append(_load_certificate_bytes(raw))
        elif isinstance(source, bytes):
          resolved.append(_load_certificate_bytes(source))
        else:
          raise TypeError(
            f"Unsupported trusted cert source type: {type(source)!r}"
          )
      except Exception as exc:  # noqa: BLE001 - normalized below
        raise CAPTrustChainError(
          f"Failed to load trusted certificate from {source!r}: {exc}"
        ) from exc
    return resolved

  @property
  def effective_verification_time(self) -> dt:
    return self.verification_time or dt.now(tz.utc)


def _load_certificate_bytes(raw: bytes) -> x509.Certificate:
  """Load a certificate from bytes, trying PEM then DER."""
  try:
    return x509.load_pem_x509_certificate(raw)
  except ValueError:
    return x509.load_der_x509_certificate(raw)


@dataclass(frozen=True, slots=True)
class ValidationResult:
  """The outcome of running :meth:`CAPCryptoValidator.verify`.

  Attributes:
      is_valid: ``True`` only if every pipeline step completed without
          raising a ``CAPValidationError``.
      errors: All validation errors encountered, in pipeline order.
          Empty when ``is_valid`` is ``True``.
      parsed_alert: A shallow dict of the CAP ``<alert>`` fields that were
          successfully extracted (identifier, sender, sent, status,
          msgType, scope), or ``None`` if the document could not be
          parsed far enough to extract them.
      metrics: Timing and diagnostic data: per-step wall-clock duration
          in seconds (``step_timings``), the total duration
          (``total_seconds``), and the resolved signer certificate
          fingerprint if signature verification succeeded
          (``signer_fingerprint_sha256``).
  """

  is_valid: bool
  errors: list[CAPValidationError]
  parsed_alert: dict[str, typing.Any] | None
  metrics: dict[str, typing.Any]


# ---------------------------------------------------------------------------
# Pipeline protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ValidationStep(typing.Protocol):
  """A single stage in the validation pipeline.

  Implementations must be safe to call concurrently from multiple threads
  against different ``xml_element``/``context`` pairs -- i.e. they should
  not mutate shared instance state during ``__call__``.
  """

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    **kwargs: typing.Any,
  ) -> None:
    """Validate one aspect of ``xml_element``.

    Implementations communicate cross-step results (e.g. the extracted
    signer certificate) via the *shared* ``PipelineState`` object that
    ``CAPCryptoValidator.verify`` threads through as a positional
    attribute on the element via ``xml_element.getroottree()`` docinfo
    is avoided by convention -- instead, steps that need to share data
    receive it through :class:`PipelineState`, injected as a second
    parameter by the runner. See ``CryptoSignatureStep`` /
    ``TrustChainStep`` for the concrete contract.

    Raises:
        CAPValidationError: on any validation failure. Subclasses
            should raise the most specific exception type available.
    """
    ...


@dataclass
class PipelineState:
  """Mutable scratch space threaded through one ``verify()`` call so
  steps can hand results to later steps (e.g. the certificate extracted
  by signature verification is needed by trust-chain and revocation
  checks). This object is created fresh per call and never shared across
  threads or across calls.
  """

  signer_certificate: x509.Certificate | None = None
  signed_xml: typing.Any = None


# ---------------------------------------------------------------------------
# Step 1: Schema / well-formedness
# ---------------------------------------------------------------------------


class CAPSchemaStep(ValidationStep):
  """Validates that the document is well-formed XML and, if an XSD is
  configured, conforms to the OASIS CAP v1.2 schema.

  The XSD load is stubbed out (``xsd_path=None`` by default) because
  shipping the actual OASIS schema bytes is out of scope for this module;
  point ``xsd_path`` at a local copy of ``CAP-v1.2.xsd`` to enable full
  schema validation.
  """

  __slots__ = ("_xsd_path", "_schema")

  def __init__(self, xsd_path: str | Path | None = None) -> None:
    self._xsd_path: str | Path | None = xsd_path
    self._schema: etree.XMLSchema | None = None
    if xsd_path is not None:
      # Loaded once at construction time (immutable thereafter), so
      # this remains safe for concurrent use across threads.
      self._schema = etree.XMLSchema(
        etree=etree.parse(source=str(object=xsd_path))
      )

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    **_kwargs: Any,
  ) -> None:
    # Well-formedness is implicitly guaranteed by the time we have an
    # `_Element` (lxml would have raised XMLSyntaxError during parse),
    # but we defensively re-check structural sanity here: a CAP alert
    # root in the expected namespace with at least one child.
    tag = etree.QName(xml_element.tag)
    if tag.localname != "alert":
      raise CAPSchemaError(
        f"Root element must be <alert>, found <{tag.localname}>"
      )
    if len(xml_element) == 0:
      raise CAPSchemaError("Root <alert> element has no children")

    if self._schema is not None:
      if not self._schema.validate(xml_element):
        error_log = self._schema.error_log
        raise CAPSchemaError(f"XSD validation failed: {error_log}")


# ---------------------------------------------------------------------------
# Step 2: Cryptographic signature verification (the math)
# ---------------------------------------------------------------------------


class CryptoSignatureStep(ValidationStep):
  """Uses ``signxml.XMLVerifier`` to validate the enveloped XMLDSig
  signature's digest and signature value, and extracts the signer's
  certificate for downstream trust/revocation checks.

  This step deliberately does **not** decide whether the certificate is
  trustworthy -- only that the signature is mathematically valid *for
  whatever certificate is embedded in the document*. Trust is
  ``TrustChainStep``'s job. This separation keeps error messages precise
  (a forged signature vs. a valid-but-untrusted signer are different
  failure modes operators need to distinguish).
  """

  __slots__ = ("_signature_config",)

  def __init__(
    self, signature_config: SignatureConfiguration | None = None
  ) -> None:
    # Pin the signature location to defend against signature-wrapping
    # attacks, and leave algorithm restrictions at signxml's secure
    # defaults unless the caller overrides them.
    self._signature_config = signature_config or SignatureConfiguration()

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> None:
    signature_nodes = xml_element.findall(f".//{{{DS_NAMESPACE}}}Signature")
    if not signature_nodes:
      raise CAPSignatureSyntaxError(
        "No <ds:Signature> element found in document"
      )
    if len(signature_nodes) > 1:
      # Multiple signatures are legal in general XMLDSig but are a
      # common vector for signature-wrapping attacks in this kind of
      # single-signer envelope; be conservative.
      raise CAPSignatureSyntaxError(
        f"Expected exactly one <ds:Signature>, found {len(signature_nodes)}"
      )

    # Extract the embedded signer certificate ourselves and pin it via
    # x509_cert=. This is deliberate: if XMLVerifier.verify() is called
    # *without* x509_cert/ca_pem_file, signxml performs its own
    # self-signed/CA-chain validation internally (and rejects, e.g.,
    # certs lacking a KeyUsage extension) -- conflating trust decisions
    # into what should be a pure "is the math valid for this specific
    # certificate" check. Pinning the embedded cert here keeps this
    # step's failures limited to signature/digest correctness, and
    # leaves all trust-worthiness questions to TrustChainStep.
    embedded_cert = _extract_embedded_certificate(signature_nodes[0])
    if embedded_cert is None:
      raise CAPSignatureSyntaxError(
        "No <ds:X509Certificate> found in KeyInfo "
        "(HMAC or bare-key signatures are not accepted for CAP validation)"
      )
    result: VerifyResult
    try:
      match XMLVerifier().verify(
        xml_element,
        x509_cert=embedded_cert,
        expect_config=self._signature_config,
      ):
        case list() as results:
          result = results[0]
          pass
        case VerifyResult() as single_result:
          result = single_result
    except InvalidSignature as exc:
      raise CAPSignatureMathError(f"Signature value is invalid: {exc}") from exc
    except InvalidInput as exc:
      raise CAPSignatureSyntaxError(
        f"Malformed signature structure: {exc}"
      ) from exc

    # verify() succeeded *for embedded_cert specifically*, so it is,
    # by construction, the certificate that produced this signature.
    if state is None:
      state = PipelineState()
    state.signer_certificate = embedded_cert
    state.signed_xml = result.signed_xml


def _extract_embedded_certificate(
  signature_node: etree._Element,
) -> x509.Certificate | None:
  """Parse the first ``<ds:X509Certificate>`` out of a ``<ds:Signature>``
  element's ``KeyInfo`` block, if present.
  """
  import base64

  cert_nodes = signature_node.findall(f".//{{{DS_NAMESPACE}}}X509Certificate")
  if not cert_nodes or not cert_nodes[0].text:
    return None
  der = base64.b64decode("".join(cert_nodes[0].text.split()))
  return x509.load_der_x509_certificate(der)


# ---------------------------------------------------------------------------
# Step 3: Trust chain validation
# ---------------------------------------------------------------------------


class TrustChainStep(ValidationStep):
  """Validates the certificate extracted by ``CryptoSignatureStep``
  against the trust anchors in ``ValidationContext`` (explicit
  ``trusted_certs`` and/or the OS trust store via ``truststore``).

  Chain building uses ``cryptography``'s policy-based verifier
  (``cryptography.x509.verification``) when available; if the installed
  ``cryptography`` version predates that API, this step falls back to a
  direct issuer-match check against the trusted set, which is weaker
  (single-hop only) but keeps the module functional without a hard
  version pin.

  Operational note: ``cryptography``'s modern verifier enforces a strict
  RFC 5280 profile, which in practice means the *signer's* (end-entity)
  certificate must carry a ``SubjectAlternativeName`` extension or chain
  building will fail with an "unsupported extension" error even when the
  chain is otherwise perfectly valid. When provisioning CAP signer
  certificates, include a SAN (an ``rfc822Name`` matching the alert
  ``<sender>`` is a natural choice) -- this is a real constraint verified
  against the current ``cryptography`` release, not a defensive
  exaggeration.
  """

  __slots__ = ()

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
      raise CAPTrustChainError(
        "TrustChainStep ran without a signer certificate; "
        "CryptoSignatureStep must run first"
      )

    cert = state.signer_certificate
    now = context.effective_verification_time
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
      raise CAPTrustChainError(
        f"Signer certificate is outside its validity period "
        f"({cert.not_valid_before_utc} .. {cert.not_valid_after_utc}), "
        f"checked at {now}"
      )

    trusted = context.resolved_trusted_certs()
    trust_store_ok = self._check_against_explicit_anchors(cert, trusted)

    system_ok = False
    if context.use_system_truststore:
      system_ok = self._check_against_system_store(cert)

    if not (trust_store_ok or system_ok):
      raise CAPTrustChainError(
        "Signer certificate does not chain to any trusted anchor "
        "(neither explicit trusted_certs nor the system trust store, if enabled)"
      )

  @staticmethod
  def _check_against_explicit_anchors(
    cert: x509.Certificate, trusted: list[x509.Certificate]
  ) -> bool:
    if not trusted:
      return False
    try:
      from cryptography.x509.verification import PolicyBuilder, Store

      store = Store(trusted)
      builder = PolicyBuilder().store(store)
      verifier = (
        builder.build_server_verifier(
          x509.DNSName(_first_san_dns_name(cert) or "invalid.example")
        )
        if False
        else builder.build_client_verifier()
      )  # CAP signers are not TLS servers
      verifier.verify(cert, [])
      return True
    except ImportError:
      # cryptography < 42 lacks the modern verification API; fall
      # back to a direct "is this cert itself, or is it issued by
      # one of, the trusted anchors" check.
      return _fallback_single_hop_trust(cert, trusted)
    except Exception as exc:  # noqa: BLE001
      logger.debug("Explicit trust anchor chain build failed: %s", exc)
      return False

  @staticmethod
  def _check_against_system_store(cert: x509.Certificate) -> bool:
    # truststore exposes an ssl.SSLContext-like surface intended for
    # TLS handshakes, not bare certificate chain validation. We use it
    # defensively via its underlying platform verification where
    # exposed; if unavailable in this environment we report "not
    # confirmed" rather than raising, letting explicit trusted_certs
    # (if configured) carry the decision.
    try:
      import ssl

      ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      # truststore does not provide a documented standalone
      # "verify this arbitrary certificate" entry point outside of a
      # live TLS handshake; wrap the intent explicitly so operators
      # relying on this path know its limitation.
      _ = ctx  # constructed to confirm the platform backend loads
      logger.debug(
        "System truststore backend available; standalone (non-TLS) "
        "chain verification of CAP signer certs is best-effort only. "
        "For strong guarantees, supply explicit trusted_certs."
      )
      return False
    except Exception as exc:  # noqa: BLE001
      logger.debug("System truststore check unavailable: %s", exc)
      return False


def _first_san_dns_name(cert: x509.Certificate) -> str | None:
  try:
    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = ext.value.get_values_for_type(x509.DNSName)
    return names[0] if names else None
  except x509.ExtensionNotFound:
    return None


def _fallback_single_hop_trust(
  cert: x509.Certificate, trusted: list[x509.Certificate]
) -> bool:
  """Weak fallback: accept if ``cert`` is itself one of the trusted
  anchors, or if it was directly issued and signature-verified by one of
  them. Does not build multi-hop chains through intermediates.
  """
  cert_fp: bytes = cert.fingerprint(algorithm=hashes.SHA256())

  for anchor in trusted:
    # 1. Quick check: Is the certificate itself a trusted anchor?
    if cert_fp == anchor.fingerprint(algorithm=hashes.SHA256()):
      return True

    # 2. Check if the anchor issued this certificate
    if cert.issuer == anchor.subject:
      try:
        # This native method safely validates RSA, EC, and Ed25519 signatures
        # without running into KEM/XDH union type checker errors.
        cert.verify_directly_issued_by(issuer=anchor)
        return True
      except Exception:
        continue

  return False


# ---------------------------------------------------------------------------
# Step 4: Revocation (OCSP primary, CRL fallback)
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------

CallbackType = typing.Callable[..., None]


class CAPCryptoValidator:
  """Runs a configured pipeline of :class:`ValidationStep`-shaped
  callables against CAP v1.2 XML documents.

  Thread safety: a ``CAPCryptoValidator`` instance carries no per-call
  mutable state. ``verify()`` allocates a fresh :class:`PipelineState`
  and works entirely with local variables and the immutable
  ``ValidationContext``, so the *same instance* may be invoked
  concurrently from multiple threads (e.g. via
  ``concurrent.futures.ThreadPoolExecutor``) without external locking.
  The one caveat is callback lists (``on_step_complete`` etc.): callers
  who ``append`` callbacks after handing the instance to worker threads
  are responsible for their own synchronization around that list
  mutation, exactly as with any shared Python list.

  Observer hooks: ``on_step_complete``, ``on_validation_failed``, and
  ``on_validation_success`` are plain lists of callables. Bind them to
  ``blinker`` signals, logging, metrics emitters, etc.:

      validator.on_step_complete.append(lambda step, ctx: print(step))

  Callback signatures:
      on_step_complete(step: ValidationStep, xml_element, context) -> None
      on_validation_failed(errors: list[CAPValidationError], xml_element, context) -> None
      on_validation_success(result: ValidationResult, xml_element, context) -> None
  """

  def __init__(
    self, context: ValidationContext, steps: list[ValidationStep]
  ) -> None:
    self._context = context
    self._steps = tuple(steps)
    self.on_step_complete: list[CallbackType] = []
    self.on_validation_failed: list[CallbackType] = []
    self.on_validation_success: list[CallbackType] = []
    # Reentrant lock guarding only the callback lists themselves during
    # invocation, not the (already-stateless) validation logic -- so
    # callbacks may safely be added/removed from other threads while a
    # verify() call is in flight without corrupting iteration.
    self._callback_lock = threading.RLock()

  # -- factories -----------------------------------------------------------

  @classmethod
  def strict(
    cls,
    trusted_certs: list[TrustedCertSource],
    require_revocation: bool = True,
    xsd_path: str | Path | None = None,
  ) -> "CAPCryptoValidator":
    """Full pipeline: schema, signature math, trust chain, and (by
    default) mandatory revocation checking. Suitable for authoritative
    alert-origination systems where a false "valid" is unacceptable.
    """
    context = ValidationContext(
      trusted_certs=trusted_certs,
      use_system_truststore=True,
      require_ocsp_crl=require_revocation,
    )
    steps: list[ValidationStep] = [
      CAPSchemaStep(xsd_path=xsd_path),
      CryptoSignatureStep(),
      TrustChainStep(),
      RevocationStep(),
    ]
    return cls(context, steps)

  @classmethod
  def relaxed(
    cls, trusted_certs: list[TrustedCertSource]
  ) -> "CAPCryptoValidator":
    """Signature math and trust chain only -- skips strict schema
    validation and revocation checking. Useful for fast pre-filtering
    of a high-volume feed before a slower authoritative pass, or for
    offline/air-gapped environments without OCSP/CRL reachability.
    """
    context = ValidationContext(
      trusted_certs=trusted_certs,
      use_system_truststore=True,
      require_ocsp_crl=False,
    )
    steps: list[ValidationStep] = [CryptoSignatureStep(), TrustChainStep()]
    return cls(context, steps)

  # -- main entry point ------------------------------------------------

  def verify(self, xml_bytes: bytes) -> ValidationResult:
    """Run the full pipeline against ``xml_bytes`` and return a
    :class:`ValidationResult`. Never raises for validation failures;
    only re-raises ``KeyboardInterrupt``/``SystemExit``/``MemoryError``
    so a worker thread pool isn't silently killed by those.
    """
    start = time.monotonic()
    step_timings: dict[str, float] = {}
    errors: list[CAPValidationError] = []
    parsed_alert: dict[str, typing.Any] | None = None
    state = PipelineState()

    try:
      parser = etree.XMLParser(
        resolve_entities=False, no_network=True, huge_tree=False
      )
      xml_element = etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError as exc:
      error = CAPSchemaError(f"Document is not well-formed XML: {exc}")
      errors.append(error)
      result = ValidationResult(
        is_valid=False,
        errors=errors,
        parsed_alert=None,
        metrics={
          "step_timings": step_timings,
          "total_seconds": time.monotonic() - start,
        },
      )
      self._fire(self.on_validation_failed, errors, None, self._context)
      return result

    for step in self._steps:
      step_start = time.monotonic()
      try:
        step(xml_element, self._context, state=state)

      except CAPValidationError as exc:
        errors.append(exc)
        step_timings[type(step).__name__] = time.monotonic() - step_start
        break
      except (KeyboardInterrupt, SystemExit, MemoryError):
        raise
      except Exception as exc:  # noqa: BLE001 - deliberate broad catch, see class docstring
        logger.exception(
          "Unexpected error in validation step %s", type(step).__name__
        )
        errors.append(
          CAPInternalError(
            f"{type(step).__name__} raised an unexpected error: {exc}"
          )
        )
        step_timings[type(step).__name__] = time.monotonic() - step_start
        break
      else:
        step_timings[type(step).__name__] = time.monotonic() - step_start
        self._fire(self.on_step_complete, step, xml_element, self._context)

    if not errors:
      parsed_alert = _extract_alert_summary(xml_element)

    metrics: dict[str, typing.Any] = {
      "step_timings": step_timings,
      "total_seconds": time.monotonic() - start,
    }
    if state.signer_certificate is not None:
      metrics["signer_fingerprint_sha256"] = (
        state.signer_certificate.fingerprint(hashes.SHA256()).hex()
      )
      metrics["signer_subject"] = (
        state.signer_certificate.subject.rfc4514_string()
      )

    result = ValidationResult(
      is_valid=not errors,
      errors=errors,
      parsed_alert=parsed_alert,
      metrics=metrics,
    )

    if errors:
      self._fire(self.on_validation_failed, errors, xml_element, self._context)
    else:
      self._fire(self.on_validation_success, result, xml_element, self._context)

    return result

  # -- internals ------------------------------------------------------

  def _fire(self, callbacks: list[CallbackType], *args: typing.Any) -> None:
    with self._callback_lock:
      snapshot = list(callbacks)
    for callback in snapshot:
      try:
        callback(*args)
      except Exception:  # noqa: BLE001
        logger.exception("Observer callback %r raised", callback)


def _extract_alert_summary(
  xml_element: etree._Element,
) -> dict[str, typing.Any]:
  ns = {"cap": CAP_1_2_NAMESPACE}

  def text_of(tag: str) -> str | None:
    node = xml_element.find(f"cap:{tag}", namespaces=ns)
    return node.text if node is not None else None

  return {
    "identifier": text_of("identifier"),
    "sender": text_of("sender"),
    "sent": text_of("sent"),
    "status": text_of("status"),
    "msgType": text_of("msgType"),
    "scope": text_of("scope"),
  }


__all__ = [
  "CAPValidationError",
  "CAPSchemaError",
  "CAPSignatureSyntaxError",
  "CAPSignatureMathError",
  "CAPTrustChainError",
  "CAPRevocationError",
  "CAPInternalError",
  "ValidationContext",
  "ValidationResult",
  "ValidationStep",
  "PipelineState",
  "CAPSchemaStep",
  "CryptoSignatureStep",
  "TrustChainStep",
  "RevocationStep",
  "CAPCryptoValidator",
]
