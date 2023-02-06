import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from harborapi.models._models import ChartMetadata as ChartMetadataGenerated
from harborapi.models._models import ChartVersion as ChartVersionGenerated
from harborapi.models._models import ReplicationFilter as ReplicationFilterGenerated
from harborapi.models._models import Search as SearchGenerated
from harborapi.models._models import SearchResult as SearchResultGenerated
from harborapi.models.models import (
    Artifact,
    ChartMetadata,
    ChartVersion,
    LdapConf,
    ReplicationFilter,
    Repository,
    Search,
    SearchResult,
    VulnerabilitySummary,
)

from .utils import (
    _no_references_check,
    _override_class_check,
    _override_compat_check,
    _override_field_check,
)


@given(st.builds(ChartMetadata), st.builds(ChartMetadataGenerated))
def test_chartmetadata_override(
    modified: ChartMetadata, generated: ChartMetadataGenerated
) -> None:
    fields = [
        "name",
        "version",
        "engine",
        "icon",
        "api_version",
        "app_version",
    ]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(ChartVersion), st.builds(ChartVersionGenerated))
def test_chartversion_override(
    modified: ChartVersion, generated: ChartVersionGenerated
) -> None:
    # we already checked fields in the ChartMetadata test

    # Don't check bases (we subclassed ChartVersion, not ChartMetadata)
    _override_class_check(modified, generated, check_bases=False)
    _override_compat_check(modified, generated)


@given(st.builds(SearchResult), st.builds(SearchResultGenerated))
def test_searchresult_override(
    modified: SearchResult, generated: SearchResultGenerated
) -> None:
    # we already checked fields in the ChartMetadata test
    _override_field_check(modified, generated, "chart")
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(Search), st.builds(SearchGenerated))
def test_search_override(modified: Search, generated: SearchGenerated) -> None:
    # we already checked fields in the ChartMetadata test
    _override_field_check(modified, generated, "chart")
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(ReplicationFilter), st.builds(ReplicationFilterGenerated))
def test_replicationfilter_override(
    modified: ReplicationFilter, generated: ReplicationFilterGenerated
) -> None:
    fields = ["value"]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@pytest.mark.parametrize("uppercase", [True, False])
def test_vulnerabilitysummary_override(uppercase: bool) -> None:
    # This model is not backwards compatible with the generated model
    # since we add the fields "low", "medium", "high" and "critical"

    # the keys of the summary dict have been observed to have the first
    # letter capitalized, so we test both cases.
    summary = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    if uppercase:
        summary = {k.title(): v for k, v in summary.items()}

    values = {
        "summary": summary,
        "total": 10,
        "fixable": 5,
    }
    v = VulnerabilitySummary(**values)
    assert v.low == 1
    assert v.medium == 2
    assert v.high == 3
    assert v.critical == 4
    assert v.total == 10
    assert v.fixable == 5


def test_search() -> None:
    # Real search result
    data = {
        "chart": [
            {
                "Chart": {
                    "apiVersion": "v2",
                    "appVersion": "1.23.1",
                    "description": "NGINX Open Source is a web server that can be also used as a reverse proxy, load balancer, and HTTP cache. Recommended for high-demanding sites due to its ability to provide faster content.",
                    "engine": None,
                    "home": "https://github.com/bitnami/charts/tree/master/bitnami/nginx",
                    "icon": "https://bitnami.com/assets/stacks/nginx/img/nginx-stack-220x234.png",
                    "keywords": ["nginx", "http", "web", "www", "reverse proxy"],
                    "name": "myproject/nginx",
                    "sources": [
                        "https://github.com/bitnami/containers/tree/main/bitnami/nginx",
                        "https://www.nginx.org",
                    ],
                    "version": "13.1.6",
                    "created": "2023-02-03T09:38:19.867594256Z",
                    "digest": "56663051192d296847e60ea81cebe03a26a703c3c6eef8f976509f80dc5e87ea",
                    "urls": ["myproject/charts/nginx-13.1.6.tgz"],
                    "labels": None,
                },
                "Name": "myproject/nginx",
            }
        ],
        "project": [],
        "repository": [],
    }
    # The original model fails to validate because the "engine" field
    # is None. This is a problem with the spec, and thus we have updated
    # the model to allow None values for this field.
    with pytest.raises(ValidationError):
        SearchGenerated(**data)
    s2 = Search(**data)
    c = s2.chart[0].chart
    assert c.engine is None
    # check that we have inherited from ChartVersion correctly
    assert c.created == "2023-02-03T09:38:19.867594256Z"
    assert c.removed is None
    assert (
        c.digest == "56663051192d296847e60ea81cebe03a26a703c3c6eef8f976509f80dc5e87ea"
    )
    assert c.urls == ["myproject/charts/nginx-13.1.6.tgz"]
    assert c.labels is None
    chartversion_fields = [
        "created",
        "removed",
        "digest",
        "urls",
        "labels",
    ]

    # Check that the fields from the generated ChartVersion
    # are inherited properly
    for field in chartversion_fields:
        _override_field_check(c, ChartVersion, field)

    # TODO: maybe test MRO of the class?


def test_no_references() -> None:
    """We assume these models are not referenced by other models when
    overriding them. In order to verify this assumption, we check all
    fields of all models and ensure that they do not reference the models
    in the `no_references` list.

    This test ensures that spec updates do not introduce new references
    to these models undetected. Should any of these models be referenced
    by other models, this test will fail.

    When we add a more dynamic way to override the models, this test will be
    obsolete.
    """
    from harborapi.models import models

    # List of models we have updated that we believe are not referenced
    # by any other models
    no_references = [Repository, Artifact, LdapConf]
    _no_references_check(models, no_references)
