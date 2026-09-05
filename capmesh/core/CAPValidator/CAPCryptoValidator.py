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

import asyncio
import base64
import hashlib
import logging
import threading
import time
import typing

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from lxml import etree

from .CAPSchemaStep import CAPSchemaStep
from .CryptoSignatureStep import CryptoSignatureStep
from .RevocationStep import RevocationStep
from .types import (
  CAPInternalError,
  CAPSchemaError,
  CAPValidationContext,
  CAPValidationError,
  PipelineState,
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
    self, context: CAPValidationContext, steps: list[ValidationStep]
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
    cls, context: CAPValidationContext | None = None
  ) -> "CAPCryptoValidator":
    """Full pipeline: schema, signature math, trust chain, and mandatory revocation checking.
    Suitable for authoritative systems where a false "valid" is unacceptable.
    """
    steps: list[ValidationStep] = [
      CAPSchemaStep(),
      CryptoSignatureStep(),
      RevocationStep(),
    ]

    return cls(context or CAPValidationContext(), steps)

  @classmethod
  def relaxed(
    cls, context: CAPValidationContext | None = None
  ) -> "CAPCryptoValidator":
    """Signature math and trust chain only -- skips online revocation checking. Useful for
    offline/air-gapped environments without OCSP/CRL reachability.
    """
    steps: list[ValidationStep] = [
      CAPSchemaStep(),
      CryptoSignatureStep(),
    ]
    return cls(context or CAPValidationContext(), steps)

  # -- main entry point ------------------------------------------------

  def verify(self, xml_bytes: bytes) -> ValidationResult:
    """Run the full pipeline against ``xml_bytes`` and return a
    :class:`ValidationResult`. Never raises for validation failures;
    only re-raises ``KeyboardInterrupt``/``SystemExit``/``MemoryError``
    so a worker thread pool isn't silently killed by those.
    """
    started = time.perf_counter()
    metrics: dict[str, typing.Any] = {"step_timings": {}}
    parsed_alert: dict[str, typing.Any] | None = None
    errors: list[CAPValidationError] = []
    xml_element: etree._Element | None = None

    try:
      parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
      )
      xml_element = etree.fromstring(xml_bytes, parser=parser)
      parsed_alert = self._parse_alert(xml_element)
      state = PipelineState()

      for step in self._steps:
        step_started = time.perf_counter()
        try:
          state = self._run_step(step, xml_element, state)
          self._fire(self.on_step_complete, step, xml_element, self._context)
        except CAPValidationError as exc:
          errors.append(exc)
          self._fire(
            self.on_validation_failed, errors, xml_element, self._context
          )
          break
        except (KeyboardInterrupt, SystemExit, MemoryError):
          raise
        except Exception as exc:  # noqa: BLE001
          error = CAPInternalError(
            f"Validation step {type(step).__name__} failed unexpectedly: {exc}"
          )
          errors.append(error)
          self._fire(
            self.on_validation_failed, errors, xml_element, self._context
          )
          break
        finally:
          metrics["step_timings"][type(step).__name__] = (
            time.perf_counter() - step_started
          )

      if not errors:
        metrics["signer_fingerprint_sha256"] = self._signer_fingerprint(state)
        result = ValidationResult(
          is_valid=True,
          errors=[],
          parsed_alert=parsed_alert,
          metrics=metrics,
        )
        self._fire(
          self.on_validation_success, result, xml_element, self._context
        )
        return self._finish(result, started)

    except (KeyboardInterrupt, SystemExit, MemoryError):
      raise
    except Exception as exc:  # noqa: BLE001
      if isinstance(exc, CAPValidationError):
        parse_error = exc
      elif isinstance(exc, etree.XMLSyntaxError):
        parse_error = CAPSchemaError(f"CAP XML is not well-formed: {exc}")
      else:
        parse_error = CAPInternalError(
          f"Unable to parse or validate CAP alert: {exc}"
        )
      errors.append(parse_error)
      if xml_element is not None:
        self._fire(
          self.on_validation_failed, errors, xml_element, self._context
        )

    result = ValidationResult(
      is_valid=False,
      errors=errors,
      parsed_alert=parsed_alert,
      metrics=metrics,
    )
    return self._finish(result, started)

  def _run_step(
    self,
    step: ValidationStep,
    xml_element: etree._Element,
    state: PipelineState,
  ) -> PipelineState:
    coroutine = step(xml_element, state=state, context=self._context)
    try:
      asyncio.get_running_loop()
    except RuntimeError:
      return asyncio.run(coroutine)

    result: list[PipelineState] = []
    failure: list[BaseException] = []

    def run() -> None:
      try:
        result.append(asyncio.run(coroutine))
      except BaseException as exc:
        failure.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join()
    if failure:
      raise failure[0]
    return result[0]

  def _finish(
    self, result: ValidationResult, started: float
  ) -> ValidationResult:
    result.metrics["total_seconds"] = time.perf_counter() - started
    return result

  @staticmethod
  def _parse_alert(xml_element: etree._Element) -> dict[str, typing.Any]:
    namespace = etree.QName(xml_element).namespace

    def text(name: str) -> str | None:
      tag = f"{{{namespace}}}{name}" if namespace else name
      return xml_element.findtext(tag)

    return {
      name: text(name)
      for name in ("identifier", "sender", "sent", "status", "msgType", "scope")
    }

  @staticmethod
  def _signer_fingerprint(state: PipelineState) -> str | None:
    result = state.verification_result
    if result is None:
      return None
    certificate = result.signature_xml.find(
      "{http://www.w3.org/2000/09/xmldsig#}KeyInfo/"
      "{http://www.w3.org/2000/09/xmldsig#}X509Data/"
      "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
    )
    if certificate is None or not certificate.text:
      return None
    encoded = base64.b64decode(certificate.text, validate=True)
    parsed = x509.load_der_x509_certificate(encoded)
    return hashlib.sha256(parsed.public_bytes(Encoding.DER)).hexdigest()

  # -- internals ------------------------------------------------------

  def _fire(self, callbacks: list[CallbackType], *args: typing.Any) -> None:
    with self._callback_lock:
      snapshot = list(callbacks)
    for callback in snapshot:
      try:
        callback(*args)
      except Exception:  # noqa: BLE001
        logger.exception("Observer callback %r raised", callback)
