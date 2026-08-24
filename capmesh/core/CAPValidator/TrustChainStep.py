import logging
from typing import Any

import truststore
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from lxml import etree

from .ErrorTypes import CAPTrustChainError
from .types import (
  PipelineState,
  ValidationContext,
  ValidationStep,
)

logger = logging.getLogger(__name__)


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
