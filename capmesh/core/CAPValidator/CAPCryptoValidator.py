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
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from lxml import etree

# Since CAP_1_2_NAMESPACE is defined at the package root level,
# we can safely import just this constant from the package,
# or redefine it locally if mypy still complains about the package root.
from . import CAP_1_2_NAMESPACE
from .CAPSchemaStep import CAPSchemaStep
from .CryptoSignatureStep import CryptoSignatureStep
from .ErrorTypes import (
  CAPInternalError,
  CAPSchemaError,
  CAPValidationError,
)
from .RevocationStep import RevocationStep
from .TrustChainStep import TrustChainStep
from .types import (
  PipelineState,
  TrustedCertSource,
  ValidationContext,
  ValidationResult,
  ValidationStep,
)

logger = logging.getLogger(__name__)

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
