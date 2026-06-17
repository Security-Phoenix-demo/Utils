#!/usr/bin/env python3
"""
TradingView Grype OCI label transforms.

Activated only when ``--tv-tags`` is passed to the import entry points.
Requires ``WORKSPACE_PREFIX`` in the runtime environment.
"""

import logging
import os
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

NEW_AUTHORS_LABEL = "org.opencontainers.image.new_authors_key"
HRDB_PREFIX = "HRDB-"
WORKSPACE_PREFIX = "WORKSPACE_PREFIX"


def get_new_authors_key_prefix() -> str:
    """Resolve the UUID prefix for TradingView new_authors_key tag transforms."""
    prefix = os.environ.get(WORKSPACE_PREFIX, "").strip()
    if not prefix:
        raise ValueError(
            f"--tv-tags requires the {WORKSPACE_PREFIX} environment variable to be set"
        )
    return prefix


def transform_new_authors_key_value(raw: str, prefix: str) -> str:
    """Transform HRDB-<id> OCI label values into <prefix>:<id> for Phoenix tags."""
    value = raw.strip()
    if value.upper().startswith(HRDB_PREFIX):
        value = value[len(HRDB_PREFIX):]
    return f"{prefix}:{value}"


def build_label_value_transforms() -> Dict[str, Callable[[str], str]]:
    """Build OCI label value transforms for TradingView Grype imports."""
    prefix = get_new_authors_key_prefix()
    return {
        NEW_AUTHORS_LABEL: lambda value, p=prefix: transform_new_authors_key_value(value, p),
    }


def apply_tv_tags_to_grype_translator(translator) -> None:
    """Attach TradingView OCI label transforms to a GrypeTranslator instance."""
    if translator.__class__.__name__ != "GrypeTranslator":
        logger.warning(
            "TradingView --tv-tags ignored: translator %s is not GrypeTranslator",
            translator.__class__.__name__,
        )
        return

    translator.label_value_transforms = build_label_value_transforms()
    logger.info("TradingView Grype tag transform enabled (--tv-tags)")
