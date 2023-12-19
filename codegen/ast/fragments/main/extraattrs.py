from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Optional

from pydantic import RootModel


class ExtraAttrs(RootModel[Optional[Dict[str, Any]]]):
    pass
