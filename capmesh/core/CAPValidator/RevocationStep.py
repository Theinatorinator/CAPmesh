# SPDX-FileCopyrightText: 2026 Logan Mamanakis <Logan.Mamanakis@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import binascii
import logging
from typing import Any, Final

from asn1crypto.x509 import Certificate as ACert
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate
from lxml import etree
from pyhanko_certvalidator import CertificateValidator
from pyhanko_certvalidator.errors import PathValidationError, RevokedError

from .types import (
  CAPRevocationError,
  CAPSignatureSyntaxError,
  CAPTrustChainError,
  CAPValidationContext,
  PipelineState,
  ValidationStep,
)

logger: logging.Logger = logging.getLogger(name=__name__)

_X509_CERTIFICATE_TAG: Final[str] = "X509Certificate"


class RevocationStep(ValidationStep):
  """Checks the signer certificate's revocation status via OCSP
  (preferred) and falls back to CRL if no OCSP responder is advertised
  or reachable.
  """

  def __init__(self) -> None:
    """
    Args:
        trust_roots: Trusted Root/Intermediate CA certificates used to
                     build the path for revocation checking. If None,
                     falls back to the OS trust store.
    """

  async def __call__(
    self,
    xml_element: etree._Element,
    context: CAPValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> PipelineState:

    if state is None:
      state = PipelineState()

    if state.verification_result is None:
      raise CAPRevocationError(
        "Can't check revocation status of non-existent certificate"
      )

    # 1. Grab signxml results out of the pipeline state.
    state.verification_result.signature_xml

    cert_element: etree._Element | None = (
      state.verification_result.signature_xml.find(
        path="{http://www.w3.org/2000/09/xmldsig#}KeyInfo/"
        "{http://www.w3.org/2000/09/xmldsig#}X509Data/"
        "{http://www.w3.org/2000/09/xmldsig#}X509Certificate"
      )
    )

    if cert_element is None or not cert_element.text:
      raise CAPSignatureSyntaxError("No embedded X509Certificate found.")

    # Load Certificate from XML
    try:
      cert_bytes: bytes = base64.b64decode(s=cert_element.text, validate=True)
      cert_obj: Certificate = x509.load_der_x509_certificate(data=cert_bytes)
    except (binascii.Error, ValueError) as exc:
      raise CAPSignatureSyntaxError(
        f"Embedded X509Certificate is malformed: {exc}"
      ) from exc

    # Validate Loaded Certificate
    try:
      validator = CertificateValidator(
        end_entity_cert=ACert.load(
          encoded_data=cert_obj.public_bytes(encoding=Encoding.DER)
        ),
        validation_context=context.revocation_context,
      )

      # Validate the certificate for our usage

      await validator.async_validate_usage(key_usage={"digital_signature"})  # type: ignore[no-untyped-call]

      logger.debug(msg="Signer certificate revocation check passed.")

    except RevokedError as exc:
      logger.warning(msg=f"CAP signer certificate has been revoked: {exc}")
      raise CAPRevocationError(
        f"The XML signer certificate has been explicitly revoked: {exc}"
      ) from exc

    except PathValidationError as exc:
      logger.warning(msg=f"CAP certificate path validation failed: {exc}")
      raise CAPTrustChainError(
        f"Certificate path/revocation check failed to complete: {exc}"
      ) from exc

    return state
