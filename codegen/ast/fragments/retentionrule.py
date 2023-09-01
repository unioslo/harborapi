from typing import Any, Dict, Optional

from pydantic import BaseModel

# Changed: change params field type
# Reason: params is a dict of Any, not a dict of dicts
# TODO: add descriptions


class RetentionRule(BaseModel):
    params: Optional[Dict[str, Any]] = None
