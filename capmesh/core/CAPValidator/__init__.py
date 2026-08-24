# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
import logging
from typing import Final

from lxml import etree
from signxml.util import namespaces

from .CAPCryptoValidator import CAPCryptoValidator
from .CAPSchemaStep import CAPSchemaStep
from .CryptoSignatureStep import CryptoSignatureStep
from .RevocationStep import RevocationStep
from .types import (
  CAPInternalError,
  CAPRevocationError,
  CAPSchemaError,
  CAPSignatureMathError,
  CAPSignatureSyntaxError,
  CAPTrustChainError,
  CAPValidationError,
  PipelineState,
  TrustedCertSource,
  ValidationContext,
  ValidationResult,
  ValidationStep,
)

logger: logging.Logger = logging.getLogger(name=__name__)

CAP_1_2_NAMESPACE: Final[str] = "urn:oasis:names:tc:emergency:cap:1.2"


logger.debug(msg=f"registering prefix capSig as namespace{namespaces.ds:s}")
etree.register_namespace(prefix="capSig", uri=namespaces.ds)


__all__: list[str] = [
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
