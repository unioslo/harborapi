"""DEPRECATED: This module will be removed in a future version.
Module kept only for backwards compatibility with old code generation scheme."""

from __future__ import annotations

import warnings

warnings.warn(
    "The harborapi.models._models module is deprecated and will be removed in a future version. Use harborapi.models.models instead.",
    DeprecationWarning,
)

from .models import *
