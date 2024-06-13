from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Optional

# Changed: change params field type
# Reason: params is a dict of Any, not a dict of dicts


class ImmutableRule(BaseModel):
    params: Optional[Dict[str, Any]] = None
