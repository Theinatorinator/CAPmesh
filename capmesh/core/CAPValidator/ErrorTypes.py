import logging
import typing

logger = logging.getLogger(__name__)


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
