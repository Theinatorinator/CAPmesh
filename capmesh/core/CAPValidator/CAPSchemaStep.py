import logging
from importlib import resources
from importlib.resources import as_file
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, Final

from lxml import etree
from lxml.etree import XMLSchema, _ElementTree
from lxml.etree._element import _Element
from lxml.etree._xmlerror import _ListErrorLog, _LogEntry

from capmesh.core.CAPValidator import PipelineState

from .ErrorTypes import CAPSchemaError
from .types import ValidationContext, ValidationStep

logger: logging.Logger = logging.getLogger(name=__name__)


def _get_bundled_schema_path() -> Traversable:
  """Returns a safe, cross-platform absolute path string to the bundled XSD."""
  schema_file: Traversable = resources.files(
    anchor="capmesh.core.CAPValidator.schemas"
  ).joinpath("CAP-v1.2.xsd")
  return schema_file


class CAPSchemaStep(ValidationStep):
  """Validates that the document is well-formed XML and, if an XSD is
  configured, conforms to the OASIS CAP v1.2 schema.

  The XSD load is stubbed out (``xsd_path=None`` by default) because
  shipping the actual OASIS schema bytes is out of scope for this module;
  point ``xsd_path`` at a local copy of ``CAP-v1.2.xsd`` to enable full
  schema validation.
  """

  __slots__ = "_schema"

  def __init__(self, xsd_path: str | Path | None = None) -> None:
    xmlschema_doc: _ElementTree[_Element]
    if xsd_path is not None:
      logger.debug(
        msg=f"Loading CAP Schema from from user supplied path {xsd_path}"
      )
      xmlschema_doc = etree.parse(source=Path(xsd_path))
    else:
      with as_file(path=_get_bundled_schema_path()) as temp_path:
        logger.debug(msg="Loading bundled CAP Schema from package resource")
        xmlschema_doc = etree.parse(source=temp_path)

    logger.debug(msg="Compiling CAP Schema into memory")

    self._schema: Final[XMLSchema] = etree.XMLSchema(etree=xmlschema_doc)
    logger.debug(msg="Successfully loaded CAP Schema")

  def __call__(
    self,
    xml_element: etree._Element,
    context: ValidationContext,
    state: PipelineState | None,
    **_kwargs: Any,
  ) -> PipelineState:
    """Validates a CAP XML element against the schema and logs the outcome."""
    if state is None:
      state = PipelineState()
    alert_id: str = xml_element.findtext(path="identifier", default="UNKNOWN")
    sender: str = xml_element.findtext(path="sender", default="UNKNOWN")

    try:
      self._schema.assertValid(etree=xml_element)
    except etree.DocumentInvalid as exc:
      errors: _ListErrorLog = exc.error_log.filter_from_errors()

      first_error: _LogEntry = errors[0]
      raise CAPSchemaError(
        f"CAP schema validation failed for alert [{alert_id:s}] with {len(errors):i} error(s). "
        f"First error: Line {first_error.line:i}: {first_error.message:s}"
      ) from exc

    logger.debug(
      msg=f"Successfully validated CAP alert {alert_id:s} from sender {sender:s}"
    )
    return state

  def _log_schema_validation_errors(
    self, alert_id: str, sender: str, error_log: _ListErrorLog
  ) -> None:
    errors: _ListErrorLog = error_log.filter_from_errors()
    formatted_errors: str = "\n".join(
      f"  - Line {e.line:i}: {e.message:s}" for e in errors
    )

    logger.error(
      msg=f"Schema validation failed for alert {alert_id:s} from sender {sender:s} {len(errors):,i}:\n{formatted_errors:s}",
    )
