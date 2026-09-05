import logging
from typing import Any

import signxml.verifier as sv
from lxml import etree
from signxml.exceptions import (
  InvalidCertificate,
  InvalidInput,
  InvalidSignature,
)
from signxml.verifier import VerifyResult

from .types import (
  CAPInternalError,
  CAPSignatureMathError,
  CAPSignatureSyntaxError,
  CAPValidationContext,
  PipelineState,
  ValidationStep,
)

logger: logging.Logger = logging.getLogger(__name__)


class CryptoSignatureStep(ValidationStep):
  """Verifies enveloped CAP signatures per CAP 1.2 Section 3.3.4.1.

  Performs cryptographic validation and populates state.verification_result
  with signxml's VerifyResult. Downstream steps can access the verified
  XML tree via state.verification_result.signed_xml.
  """

  def __init__(self) -> None:
    """
    Args:
        trusted_ca_pem: The trusted Root/Intermediate CA bundle.
                        If None, relies on the OS trust store.
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

    try:
      # Executes verification. x509_cert securely anchors the trust path.
      verify_results: VerifyResult | list[VerifyResult] = (
        sv.XMLVerifier().verify(
          data=xml_element,
          expect_config=context.signature_configuration,
        )
      )

      if isinstance(verify_results, list):
        if len(verify_results) > 1:
          raise CAPSignatureSyntaxError(
            "Alert contains more than one signature"
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
      raise CAPSignatureSyntaxError(
        f"Alert is unsigned or signature structure is malformed: {exc}"
      ) from exc

    except (InvalidCertificate, InvalidSignature) as exc:
      raise CAPSignatureMathError(
        f"CAP Alert signature validation failed: {exc}"
      ) from exc

    except Exception as exc:
      raise CAPInternalError(
        f"Unexpected error during CAP signature verification: {exc}"
      ) from exc

    return state
