# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=93922147fe3c52f096496eb6788b9a74 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared process-group cleanup helpers for bounded fail-closed runners.

Without a child subreaper, a descendant whose parent exited is reparented to
PID 1 and its zombie persists until the system init reaps it, which makes
bounded process-group cleanup verification racy under load.  Runners that
spawn command trees must declare themselves a child subreaper before spawning
and reap reparented orphans inside their bounded group-exit wait loops.
"""
from __future__ import annotations

import ctypes
import os
import sys

_PR_SET_CHILD_SUBREAPER = 36


def become_child_subreaper() -> None:
    """Reparent orphaned descendants to this process for deterministic reaping.

    Failure to set the flag fails closed so cleanup verification never relies
    on the system init's reaping latency.
    """
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno()
        raise RuntimeError(
            f"cannot become child subreaper: errno {error_number}"
        )


def reap_exited_children() -> None:
    """Reap any exited child (including reparented orphan descendants).

    A no-op when there are no exited children; never blocks.
    """
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        pass
