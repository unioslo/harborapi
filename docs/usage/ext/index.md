# `harborapi.ext`: Extended functionality

!!! note
    This module is for advanced users only. It's highly recommended to become familiar with the regular endpoint methods first, then come back to `harborapi.ext` if you need more advanced functionality such as concurrent requests, bulk operations, and aggregation of artifact vulnerabilities.

    For the vast majority of use cases, the regular endpoint methods are sufficient.

The `harborapi.ext` module contains extensions and utility functions that are not part of the Harbor API spec. It expands the functionality of `harborapi` by providing additional
functionality for common task such as fetching artifacts in bulk from multiple repositories. These functions are primarily found in [`harborapi.ext.api`](../../reference/ext/api.md).

`harborapi.ext` also provides models used to combine multiple Harbor API models and aggregate their data. See:

* [`harborapi.ext.artifact.ArtifactInfo`](./artifact.md)
* [`harborapi.ext.report.ArtifactReport`](./report.md)


To get a practical understanding of the module, check out some recipes that use it:

* [Fetch artifacts concurrently](../../recipes/ext/conc-artifact.md)
* [Get artifact owner](../../recipes/ext/artifactowner.md)
* [Get vulnerabilities for all artifacts](../../recipes/ext/artifact-vulns.md)
* [Fetch repositories concurrently](../../recipes/ext/conc-repo.md)


!!!warning The `harborapi.ext` module is not part of the Harbor API specification and is not guaranteed to be stable. It may change in future versions of `harborapi`.

Importing `harborapi.ext` is optional and does not require any additional dependencies.

```py
import harborapi.ext
# or
from harborapi import ext
# or
from harborapi.ext import api, artifact, cve, report
# or
from harborapi.ext.api import get_artifact_info, get_artifact_vulnerabilities #, ...
```

Your IDE should provide auto-completion for the various imports available from the `harborapi.ext` module. Otherwise, check the [Reference](/reference)
