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
import typing

from blinker import signal
from blinker.base import NamedSignal
from lxml import etree

from .CAPSchemaStep import CAPSchemaStep
from .CryptoSignatureStep import CryptoSignatureStep
from .RevocationStep import RevocationStep
from .types import (
  CAPInternalError,
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
    self._context: CAPValidationContext = context
    self._steps: tuple[ValidationStep, ...] = tuple(steps)

    self.on_step_complete: NamedSignal = signal("step-complete")
    self.on_validation_failed: NamedSignal = signal("validation-failed")
    self.on_validation_success: NamedSignal = signal("validation_success")

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

  async def verify(self, xml_element: etree._Element) -> ValidationResult:
    """Run the full pipeline against ``xml_bytes`` and return a
    :class:`ValidationResult`. Never raises for validation failures;
    only re-raises ``KeyboardInterrupt``/``SystemExit``/``MemoryError``
    so a worker thread pool isn't silently killed by those.
    """
    errors: list[CAPValidationError] = []

    state: PipelineState = PipelineState()
    try:
      for step in self._steps:
        try:
          state = await step(xml_element, state=state, context=self._context)
          self.on_step_complete.send(
            self, step=step, xml_element=xml_element, context=self._context
          )
        except CAPValidationError as exc:
          errors.append(exc)
          self.on_validation_failed.send(
            self,
            step=step,
            errors=errors,
            xml_element=xml_element,
            context=self._context,
          )
          break
        except (KeyboardInterrupt, SystemExit, MemoryError):
          raise
        except Exception as exc:
          error = CAPInternalError(
            f"Validation step {type(step).__name__} failed unexpectedly: {exc}"
          )
          errors.append(error)
          self.on_validation_failed.send(
            self,
            step=step,
            errors=errors,
            xml_element=xml_element,
            context=self._context,
          )
          break

      if not errors:
        result = ValidationResult(
          is_valid=True,
          errors=[],
          verification_result=state.verification_result,
        )

        self.on_validation_success.send(
          self, result=result, xml_element=xml_element, context=self._context
        )
        return result

    except (KeyboardInterrupt, SystemExit, MemoryError):
      raise
    except Exception as exc:  # noqa: BLE001
      errors.append(
        CAPInternalError(f"Unable to parse or validate CAP alert: {exc}")
      )
      if xml_element is not None:
        self.on_validation_failed.send(
          self, errors=errors, xml_element=xml_element, context=self._context
        )

    result = ValidationResult(
      is_valid=False,
      errors=errors,
      verification_result=state.verification_result,
    )
    return result
