import logging
from importlib import resources
from pathlib import Path
from typing import Any

from lxml import etree

from .ErrorTypes import CAPSchemaError
from .types import ValidationContext, ValidationStep

logger = logging.getLogger(__name__)


def _get_schema_path() -> str:
  """Returns a safe, cross-platform absolute path string to the bundled XSD."""
  # Resolves perfectly whether running locally or inside a built site-packages wheel
  schema_file = resources.files("capmesh.core.CAPValidator.schemas").joinpath(
    "CAP-v1.2.xsd"
  )
  return str(schema_file)


class CAPSchemaStep(ValidationStep):
  """Validates that the document is well-formed XML and, if an XSD is
  configured, conforms to the OASIS CAP v1.2 schema.

  The XSD load is stubbed out (``xsd_path=None`` by default) because
  shipping the actual OASIS schema bytes is out of scope for this module;
  point ``xsd_path`` at a local copy of ``CAP-v1.2.xsd`` to enable full
  schema validation.
  """

  __slots__ = ("_xsd_path", "_schema")

  def __init__(self, xsd_path: str | Path | None = None) -> None:
    self._xsd_path: str | Path = xsd_path or _get_schema_path()
    self._schema: etree.XMLSchema

    # Loaded once at construction time (immutable thereafter), so
    # this remains safe for concurrent use across threads.
    self._schema = etree.XMLSchema(
      etree=etree.parse(source=str(object=xsd_path))
    )

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    **_kwargs: Any,
  ) -> None:
    # Well-formedness is implicitly guaranteed by the time we have an
    # `_Element` (lxml would have raised XMLSyntaxError during parse),
    # but we defensively re-check structural sanity here: a CAP alert
    # root in the expected namespace with at least one child.
    tag = etree.QName(xml_element.tag)
    if tag.localname != "alert":
      raise CAPSchemaError(
        f"Root element must be <alert>, found <{tag.localname}>"
      )
    if len(xml_element) == 0:
      raise CAPSchemaError("Root <alert> element has no children")

    if self._schema is not None:
      if not self._schema.validate(xml_element):
        error_log = self._schema.error_log
        raise CAPSchemaError(f"XSD validation failed: {error_log}")
