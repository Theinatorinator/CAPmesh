import logging
import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime as dt
from datetime import timezone as tz
from pathlib import Path
from typing import Any

from cryptography import x509
from lxml import etree
from signxml.verifier import VerifyResult

from . import (
  CAPTrustChainError,
  CAPValidationError,
)

# A type alias (PEP 695 style, Python 3.12+/3.13) describing the flexible
# ways trusted certificate material may be supplied.
type TrustedCertSource = str | Path | bytes | x509.Certificate


logger = logging.getLogger(__name__)


def _load_certificate_bytes(raw: bytes) -> x509.Certificate:
  """Load a certificate from bytes, trying PEM then DER."""
  try:
    return x509.load_pem_x509_certificate(raw)
  except ValueError:
    return x509.load_der_x509_certificate(raw)


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


@dataclass
class PipelineState:
  """Mutable scratch space threaded through one ``verify()`` call so
  steps can hand results to later steps (e.g. the certificate extracted
  by signature verification is needed by trust-chain and revocation
  checks). This object is created fresh per call and never shared across
  threads or across calls.
  """

  signed_xml: typing.Any = None
  verification_result: VerifyResult | None = None


class ValidationStep(ABC):
  """A single stage in the validation pipeline.

  Implementations must be safe to call concurrently from multiple threads
  against different ``xml_element``/``context`` pairs -- i.e. they should
  not mutate shared instance state during ``__call__``.
  """

  @abstractmethod
  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None,
    **_kwargs: Any,
  ) -> PipelineState:
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
