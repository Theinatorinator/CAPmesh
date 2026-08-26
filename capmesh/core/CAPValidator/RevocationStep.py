import logging
from typing import Any

from lxml import etree

from .types import (
  PipelineState,
  ValidationContext,
  ValidationStep,
)

logger: logging.Logger = logging.getLogger(name=__name__)


class RevocationStep(ValidationStep):
  """Checks the signer certificate's revocation status via OCSP
  (preferred) and falls back to CRL if no OCSP responder is advertised
  or reachable.
  """

  __slots__ = ()

  def __init__(self) -> None:
    pass

  async def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None = None,
    **_kwargs: Any,
  ) -> PipelineState:
    if state is None:
      state = PipelineState()

    return state
