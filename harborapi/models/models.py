"""Models for the Harbor API.

This module imports all auto generated models from the _models module,
and then overrides the models that have broken or incomplete definitions.

Furthermore, some models are extended with new validators and/or methods.
"""

# In the future, it would maybe be better to use a metaclass
# to override specific attributes on model fields, but that's
# a bit too complicated for now.
# Alternatively, we could add some sort of _fields_override field to each model,
# where we could specify the fields that need to be overridden. But how to
# specify WHAT to override could be very complicated. Overriding field values
# is one thing, but changing the type of the field is another thing entirely.
# To override field values, look at the optional_field function below, but this
# only gives us a new FieldInfo object, and does nothing to the actual field type
# that Pydantic uses.
#
# If we want to make the process of overriding fields more dynamic and
# less error prone, we need to look at how we can override the
# field type itself.


from typing import Any, Dict, List, Optional
from typing import Type as TType
from typing import Union

from loguru import logger
from pydantic import AnyUrl, Extra, Field, root_validator
from pydantic.fields import FieldInfo

# TODO: import each model individually, and avoid * import
from ._models import *
from .base import BaseModel


def _field_info(model: TType[BaseModel], field: str) -> FieldInfo:
    return model.__fields__[field].field_info


def optional_field(model: TType[BaseModel], field: str, **kwargs: Any) -> FieldInfo:
    finfo = _field_info(model, field)
    field_kwargs = dict(
        allow_mutation=finfo.allow_mutation,
        alias=finfo.alias,
        const=finfo.const,
        decimal_places=finfo.decimal_places,
        default_factory=finfo.default_factory,
        description=finfo.description,
        discriminator=finfo.discriminator,
        exclude=finfo.exclude,
        ge=finfo.ge,
        gt=finfo.gt,
        include=finfo.include,
        le=finfo.le,
        lt=finfo.lt,
        max_digits=finfo.max_digits,
        max_items=finfo.max_items,
        max_length=finfo.max_length,
        min_items=finfo.min_items,
        min_length=finfo.min_length,
        multiple_of=finfo.multiple_of,
        regex=finfo.regex,
        title=finfo.title,
        unique_items=finfo.unique_items,
    )

    # extra is the name of the extra kwargs passed to the Field constructor
    # Pop it from kwargs, and update it with the extra kwargs from the
    # original field
    extra = kwargs.pop("extra", {})
    field_extra = finfo.extra or {}
    extra.update(field_extra)

    # Use remaining kwargs to update the field kwargs
    field_kwargs.update(kwargs)

    # pydantic.Field has Any as type, but it seems to return FieldInfo (?)
    return Field(  # type: ignore
        None,
        **field_kwargs,
        **extra,
    )


# Shadow broken models with new definitions


class ChartMetadata(ChartMetadata):
    # NOTE: only 'engine' has proven to be broken so far, but that makes
    # me less likely to trust that other "required" fields are actually
    # required. So we make all fields optional for now.
    name: Optional[str] = optional_field(ChartMetadata, "name")  # type: ignore
    version: Optional[str] = optional_field(ChartMetadata, "version")  # type: ignore
    engine: Optional[str] = optional_field(ChartMetadata, "engine")  # type: ignore
    icon: Optional[str] = optional_field(ChartMetadata, "icon")  # type: ignore
    api_version: Optional[str] = optional_field(ChartMetadata, "api_version")  # type: ignore
    app_version: Optional[str] = optional_field(ChartMetadata, "app_version")  # type: ignore


# Add new methods to the model
class Repository(Repository):
    @property
    def base_name(self) -> str:
        """The repository name without the project name

        Returns
        -------
        Optional[str]
            The basename of the repository name
        """
        s = self.split_name()
        return s[1] if s else ""

    @property
    def project_name(self) -> str:
        """The name of the project that the repository belongs to

        Returns
        -------
        Optional[str]
            The name of the project that the repository belongs to
        """
        s = self.split_name()
        return s[0] if s else ""

    # TODO: cache?
    def split_name(self) -> Optional[List[str]]:
        """Split name into tuple of project and repository name

        Returns
        -------
        Optional[List[str]]
            The tuple of <project> and <repo>
        """
        if not self.name:
            return None
        components = self.name.split("/", 1)
        if len(components) == 1:  # no slash in name
            # Shouldn't happen, but we account for it anyway
            logger.warning(
                "Repository '{}' name is not in the format <project>/<repo>", self.name
            )
            return None
        return components


class ScanOverview(ScanOverview):
    """Constructs a scan overview from a dict of `mime_type:scan_overview`

    The API spec does not specify the contents of the scan overview, but from
    investigating the behavior of the API, it seems to return a dict that looks like this:

    ```py
    {
        "application/vnd.security.vulnerability.report; version=1.1": {
            # dict that conforms to NativeReportSummary spec
            ...
        }
    }
    ```

    The `__new__` method constructs a `NativeReportSummary` object and returns it
    if the MIME type is one of the two MIME types specified in the spec.

    If the MIME type is not recognized, `__new__` returns a `ScanOverview` object
    with the dict assigned as an extra attribute. This behavior is not specified.
    """

    # TODO: make this way less hacky
    def __new__(  # type: ignore # mypy doesn't like __new__ that returns different classes
        cls, *args: Any, **kwargs: Any
    ) -> Union["ScanOverview", NativeReportSummary]:
        mime_types = (
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1",
        )
        for k, v in kwargs.items():
            if k in mime_types:
                return NativeReportSummary(**v)
        # add logging call here
        return super().__new__(cls)

    class Config:
        extra = Extra.allow


class VulnerabilitySummary(VulnerabilitySummary):
    # We expand the model with these fields, which are usually
    # present in the summary dict. To provide a better interface
    # for accessing these values, they are exposed as top-level
    # fields.
    critical: int = Field(
        0,
        alias="Critical",
        description="The number of critical vulnerabilities detected.",
    )
    high: int = Field(
        0, alias="High", description="The number of critical vulnerabilities detected."
    )
    medium: int = Field(
        0,
        alias="Medium",
        description="The number of critical vulnerabilities detected.",
    )
    low: int = Field(
        0, alias="Low", description="The number of critical vulnerabilities detected."
    )

    @root_validator(pre=True)
    def assign_severity_breakdown(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        summary = values.get("summary", {})
        if not isinstance(summary, dict):
            raise ValueError("'summary' must be a dict")
        return {**values, **summary}


class ScannerRegistration(ScannerRegistration):
    # this has been observed to have values that do not comply with
    # the AnyUrl pydantic type
    url: Optional[str] = optional_field(ScannerRegistration, "url")  # type: ignore


class ReplicationFilter(ReplicationFilter):
    # Type of 'value' changed from Dict[str, Any], as the type of
    # values this field was observed to receive was exclusively strings.
    # In order to not completely break if we do receive a dict, this field
    # also accepts a dict.
    value: Optional[Union[str, Dict[str, Any]]] = optional_field(
        ReplicationFilter, "value"
    )  # type: ignore
