#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=2408c0989bec5a57b37b49eb9e345fd0 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Fail-closed boundary for the not-yet-materialized Guix executor.

An earlier Phase 46 draft accepted a caller-supplied Python callback and then
treated its booleans as evidence for daemon isolation, independent builds and
closure equality.  That is not an authentication boundary.  Until one fixed,
publisher-authenticated executor independently binds and remeasures the client,
two daemon/Store contexts, channels, substitute ACL, source snapshot, commands,
outputs and cleanup, no in-process handle can be accepted or deserialized.

Phase 37/38 may import this nominal type for an additive future injection point,
but the current workspace has no constructor or activation factory.  Discovery
of Store-resident tools therefore remains diagnostic and can never execute Guix.
"""
from __future__ import annotations

from pathlib import Path
from typing import NoReturn

try:
    from .guix_backend import PolicyError
except ImportError:  # Installed Guix Center sibling module.
    from guix_backend import PolicyError  # type: ignore[no-redef]


BLOCKER = "BLOCKED_PHASE46_FIXED_AUTHENTICATED_GUIX_EXECUTOR_NOT_MATERIALIZED"


class VerifiedGuixExecutionProfile:
    """Placeholder for a future native handle, with no accepted Python path."""

    __slots__ = ()

    def __new__(cls, *_arguments: object, **_keywords: object) -> NoReturn:
        raise PolicyError(BLOCKER)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Guix execution profiles are non-serializable")


def execute_derivation_matrix(
    profile: object,
    *,
    os_root: Path,
    output_root: Path,
) -> NoReturn:
    """Reject every value until the complete measured executor is installed."""

    del profile, os_root, output_root
    raise PolicyError(BLOCKER)


__all__ = [
    "BLOCKER",
    "VerifiedGuixExecutionProfile",
    "execute_derivation_matrix",
]
