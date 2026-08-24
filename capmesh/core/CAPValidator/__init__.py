# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
from datetime import timedelta

from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512

from .CAPCryptoValidator import CAPCryptoValidator
from .CAPSchemaStep import CAPSchemaStep
from .CryptoSignatureStep import CryptoSignatureStep
from .ErrorTypes import (
  CAPInternalError,
  CAPRevocationError,
  CAPSchemaError,
  CAPSignatureMathError,
  CAPSignatureSyntaxError,
  CAPTrustChainError,
  CAPValidationError,
)
from .RevocationStep import RevocationStep
from .types import (
  PipelineState,
  TrustedCertSource,
  ValidationContext,
  ValidationResult,
  ValidationStep,
)

logger = logging.getLogger(__name__)

CAP_1_2_NAMESPACE = "urn:oasis:names:tc:emergency:cap:1.2"
DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
_MAX_RESPONSE_AGE = timedelta(days=7)
_CLOCK_SKEW = timedelta(minutes=5)
_ALLOWED_HASH_ALGORITHMS = (SHA256, SHA384, SHA512)

__all__ = [
  "CAPSignatureSyntaxError",
  "CAPSignatureMathError",
  "CAPTrustChainError",
  "CAPRevocationError",
  "CAPInternalError",
  "CAPSchemaError",
  "CAPValidationError",
  "ValidationContext",
  "ValidationResult",
  "ValidationStep",
  "PipelineState",
  "CAPSchemaStep",
  "CryptoSignatureStep",
  "RevocationStep",
  "CAPCryptoValidator",
  "TrustedCertSource",
]
