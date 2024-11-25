# /replication/adapterinfos returns a dict of RegistryProviderInfo objects,
# where each key is the name of registry provider.
# There is no model for this in the spec.
from __future__ import annotations

from typing import Dict

from pydantic import Field


class RegistryProviders(RootModel[Dict[str, RegistryProviderInfo]]):
    root: Dict[str, RegistryProviderInfo] = Field(
        default={},
        description="The registry providers. Each key is the name of the registry provider.",
    )
