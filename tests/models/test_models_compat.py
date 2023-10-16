"""Tests for models modules with a leading underscore in their name.

In previous versions of harborapi, models were defined in modules with a leading
underscore in their name, and then fixes were applied in models with the same
name without the leading underscore. In order to maintain backwards compatibility,
the underscore modules are still present, but they are deprecated and will be removed
in a future version.
"""
from __future__ import annotations

import pytest

# These tests could be flaky! Not sure.
# We just import both modules and check that the underscore modules contain
# the same classes as the non-underscore modules.


def test_models_import() -> None:
    from harborapi.models import models

    # Importing the underscore module should emit a DeprecationWarning
    with pytest.deprecated_call():
        from harborapi.models import _models

    for model_name in dir(models):
        if model_name.startswith("_"):
            continue
        if not model_name[0].isupper():
            continue
        assert getattr(models, model_name) == getattr(_models, model_name)


def test_scanner_import() -> None:
    from harborapi.models import scanner

    with pytest.deprecated_call():
        from harborapi.models import _scanner

    for model_name in dir(scanner):
        if model_name.startswith("_"):
            continue
        if not model_name[0].isupper():
            continue
        assert getattr(scanner, model_name) == getattr(_scanner, model_name)
