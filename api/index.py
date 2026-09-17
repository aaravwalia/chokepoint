"""Vercel entry point.

Vercel's Python runtime looks for an ASGI application exported as ``app``.
The repository root goes on sys.path first so that ``chokepoint`` imports
exactly as it does locally, and the same snapshot is served either way.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chokepoint.app import app  # noqa: E402

__all__ = ["app"]
