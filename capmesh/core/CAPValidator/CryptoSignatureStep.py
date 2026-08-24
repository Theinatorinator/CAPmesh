import base64
import logging
from typing import Any

from cryptography import x509
from lxml import etree
from signxml.exceptions import InvalidInput, InvalidSignature
from signxml.verifier import SignatureConfiguration, VerifyResult, XMLVerifier

from . import DS_NAMESPACE
from .ErrorTypes import CAPSignatureMathError, CAPSignatureSyntaxError
from .types import (
  PipelineState,
  ValidationContext,
  ValidationStep,
)

logger = logging.getLogger(__name__)


def _extract_embedded_certificate(
  signature_node: etree._Element,
) -> x509.Certificate | None:
  """Parse the first ``<ds:X509Certificate>`` out of a ``<ds:Signature>``
  element's ``KeyInfo`` block, if present.
  """

  cert_nodes = signature_node.findall(f".//{{{DS_NAMESPACE}}}X509Certificate")
  if not cert_nodes or not cert_nodes[0].text:
    return None
  der = base64.b64decode("".join(cert_nodes[0].text.split()))
  return x509.load_der_x509_certificate(der)


class CryptoSignatureStep(ValidationStep):
  """Uses ``signxml.XMLVerifier`` to validate the enveloped XMLDSig
  signature's digest and signature value, and extracts the signer's
  certificate for downstream trust/revocation checks.

  This step deliberately does **not** decide whether the certificate is
  trustworthy -- only that the signature is mathematically valid *for
  whatever certificate is embedded in the document*. Trust is
  ``TrustChainStep``'s job. This separation keeps error messages precise
  (a forged signature vs. a valid-but-untrusted signer are different
  failure modes operators need to distinguish).
  """

  __slots__ = ("_signature_config",)

  def __init__(
    self, signature_config: SignatureConfiguration | None = None
  ) -> None:
    # Pin the signature location to defend against signature-wrapping
    # attacks, and leave algorithm restrictions at signxml's secure
    # defaults unless the caller overrides them.
    self._signature_config = signature_config or SignatureConfiguration()

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> None:
    signature_nodes = xml_element.findall(f".//{{{DS_NAMESPACE}}}Signature")
    if not signature_nodes:
      raise CAPSignatureSyntaxError(
        "No <ds:Signature> element found in document"
      )
    if len(signature_nodes) > 1:
      # Multiple signatures are legal in general XMLDSig but are a
      # common vector for signature-wrapping attacks in this kind of
      # single-signer envelope; be conservative.
      raise CAPSignatureSyntaxError(
        f"Expected exactly one <ds:Signature>, found {len(signature_nodes)}"
      )

    # Extract the embedded signer certificate ourselves and pin it via
    # x509_cert=. This is deliberate: if XMLVerifier.verify() is called
    # *without* x509_cert/ca_pem_file, signxml performs its own
    # self-signed/CA-chain validation internally (and rejects, e.g.,
    # certs lacking a KeyUsage extension) -- conflating trust decisions
    # into what should be a pure "is the math valid for this specific
    # certificate" check. Pinning the embedded cert here keeps this
    # step's failures limited to signature/digest correctness, and
    # leaves all trust-worthiness questions to TrustChainStep.
    embedded_cert = _extract_embedded_certificate(signature_nodes[0])
    if embedded_cert is None:
      raise CAPSignatureSyntaxError(
        "No <ds:X509Certificate> found in KeyInfo "
        "(HMAC or bare-key signatures are not accepted for CAP validation)"
      )
    result: VerifyResult
    try:
      match XMLVerifier().verify(
        xml_element,
        x509_cert=embedded_cert,
        expect_config=self._signature_config,
      ):
        case list() as results:
          result = results[0]
          pass
        case VerifyResult() as single_result:
          result = single_result
    except InvalidSignature as exc:
      raise CAPSignatureMathError(f"Signature value is invalid: {exc}") from exc
    except InvalidInput as exc:
      raise CAPSignatureSyntaxError(
        f"Malformed signature structure: {exc}"
      ) from exc

    # verify() succeeded *for embedded_cert specifically*, so it is,
    # by construction, the certificate that produced this signature.
    if state is None:
      state = PipelineState()
    state.signer_certificate = embedded_cert
    state.signed_xml = result.signed_xml
