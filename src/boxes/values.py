"""Consistent display/env stringification for typed parameter values."""

from __future__ import annotations


def format_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
