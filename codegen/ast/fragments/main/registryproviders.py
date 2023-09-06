# /replication/adapterinfos returns a dict of RegistryProviderInfo objects,
# where each key is the name of registry provider.
# There is no model for this in the spec.
from __future__ import annotations

from typing import Dict

from pydantic import Field
from pydantic import RootModel


class RegistryProviders(RootModel[Dict[str, RegistryProviderInfo]]):
    root: Dict[str, RegistryProviderInfo] = Field(
        {},
        description="The registry providers. Each key is the name of the registry provider.",
    )

    @property
    def providers(self) -> Dict[str, RegistryProviderInfo]:
        return self.root

    def __getitem__(self, key: str) -> RegistryProviderInfo:
        return self.root[key]
