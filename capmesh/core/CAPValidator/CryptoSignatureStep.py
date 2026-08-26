import logging
from typing import Any, Final

import signxml.verifier as sv
from cryptography import x509
from cryptography.x509 import Certificate
from lxml import etree
from signxml.exceptions import (
  InvalidCertificate,
  InvalidInput,
  InvalidSignature,
)
from signxml.verifier import SignatureConfiguration, VerifyResult

from .types import PipelineState, ValidationContext, ValidationStep

logger: logging.Logger = logging.getLogger(__name__)


class CryptoSignatureStep(ValidationStep):
  """Verifies enveloped CAP signatures per CAP 1.2 Section 3.3.4.1.

  Performs cryptographic validation and populates state.verification_result
  with signxml's VerifyResult. Downstream steps can access the verified
  XML tree via state.verification_result.signed_xml.
  """

  __slots__ = ("_signature_config", "_trusted_ca_pem")

  def __init__(
    self,
    trusted_ca_pem: Certificate,
    signature_config: SignatureConfiguration | None = None,
  ) -> None:
    """
    Args:
        trusted_ca_pem: The trusted Root/Intermediate CA bundle.
                        If None, relies on the OS trust store.
    """
    self._trusted_ca_pem: Final[x509.Certificate] = trusted_ca_pem
    self._signature_config: SignatureConfiguration = (
      signature_config or SignatureConfiguration()
    )

  async def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> PipelineState:
    if state is None:
      state = PipelineState()

    try:
      # Executes verification. x509_cert securely anchors the trust path.
      verify_results: VerifyResult | list[VerifyResult] = (
        sv.XMLVerifier().verify(
          data=xml_element,
          x509_cert=self._trusted_ca_pem,
          expect_config=self._signature_config,
        )
      )

      # verify() returns a list if multiple signatures exist, or a single VerifyResult
      result: VerifyResult = (
        verify_results[0]
        if isinstance(verify_results, list)
        else verify_results
      )

      state.verification_result = result
      logger.debug(msg="CAP Signature successfully verified.")

    except InvalidInput as exc:
      logger.info(
        msg=f"Alert is unsigned or signature structure is malformed: {exc}"
      )

    except (InvalidCertificate, InvalidSignature) as exc:
      logger.warning(msg=f"CAP Alert signature validation failed: {exc}")

    except Exception as exc:
      logger.error(
        msg=f"Unexpected error during CAP signature verification: {exc}"
      )

    return state
