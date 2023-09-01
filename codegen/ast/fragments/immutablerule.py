from typing import Any, Dict, Optional

from pydantic import BaseModel

# Changed: change params field type
# Reason: params is a dict of Any, not a dict of dicts


class ImmutableRule(BaseModel):
    params: Optional[Dict[str, Any]] = None
