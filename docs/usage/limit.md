# Limiting results

Certain endpoints return a list of results. For example, [`HarborAsyncClient.get_artifacts`][harborapi.HarborAsyncClient.get_artifacts] returns a list of [`Artifact`][harborapi.models.Artifact]s. By default, the number of results returned is uncapped. This can be a problem if the endpoint returns a large number of results, but you are only interested in a subset of them.

To that end, the `limit` parameter is available for all these methods. It can be used to limit the number of results returned. For example, if you only want to retrieve the first 10 artifacts, you can pass `limit=10` to `get_artifacts`:

```py hl_lines="4"
artifacts = await client.get_artifacts(
    "project",
    "repository",
    limit=10,
)
```
