"""The ext module contains extensions and utility functions that are not
part of the Harbor API.

It expands the functionality of the Harbor API by providing additional
functionality for common task such as fetching all artifacts and their
vulnerabilities in one or more repository or project.

Furthermore, it contains models for combining multiple Harbor API models
and aggregating their data.


----------------

Notes on `ArtifactInfo` vs `ArtifactReport`


The `ArtifactInfo` and ArtifactReport models are similar in that they both
provide similar interfaces, but the data they operate on is different:

`ArtifactInfo` operates on a single artifact and its associated vulnerabilities.
It provides methods for filtering vulnerabilities by severity, and for getting individual
vulnerabilities and their distribution.

`ArtifactReport` operates on a list of ArtifactInfo objects. It provides methods
for aggregating information from multiple artifacts.

`with_*` methods on `ArtifactReport` return a new `ArtifactReport` object with
the artifacts filtered by the given criteria, while `with_*` methods on
`ArtifactInfo` return a list of vulnerabilities that match the criteria.
This difference can be summarized as the following:

    ArtifactInfo.with_* -> List[Vulnerability]
    ArtifactReport.with_* -> ArtifactReport

"""
from .api import *
from .artifact import ArtifactInfo
from .cve import *
from .report import ArtifactReport, Vulnerability
