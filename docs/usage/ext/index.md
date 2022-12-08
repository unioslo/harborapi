# `ext`: Extended functionality

The `harborapi.ext` module contains extensions and utility functions that are not part of the Harbor API. It expands the functionality of the `harborapi` by providing additional
functionality for common task such as fetching artifacts in bulk from multiple repositories. See: [`harborapi.ext.api`](../../reference/ext/api.md)

Furthermore, it contains models for combining multiple Harbor API models and aggregating their data. See: [Artifact Info](./artifact.md) and [Report](./report.md)

The `harborapi.ext` module is not part of the Harbor API specification and is not guaranteed to be stable. It may change in future versions of `harborapi`.

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
