#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d0e3bc146f815f2c9026ab79efd50f00 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Deterministic presentation and accessibility model for Guix Center.

This module is not a second GUI toolkit.  It is the closed UI policy consumed
by the Qt 6/PySide 6 frontend and by headless validation.  It lets the project
verify page inventory, state handling, keyboard navigation, accessibility
names, and responsive layout without pretending that headless JSON is a Qt
runtime test.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Final, Mapping

FORMAT: Final[str] = "securityops-guix-center-ui-model/1"
SNAPSHOT_FORMAT: Final[str] = "securityops-guix-center-ui-snapshot/1"
DOMAIN: Final[bytes] = b"SECURITYOPS-GUIX-CENTER-UI-MODEL-V1\x00"
SNAPSHOT_DOMAIN: Final[bytes] = b"SECURITYOPS-GUIX-CENTER-UI-SNAPSHOT-V1\x00"

PAGE_STATES: Final[tuple[str, ...]] = (
    "loading",
    "empty",
    "ready",
    "stale",
    "offline",
    "error",
)
SCALE_FACTORS: Final[tuple[float, ...]] = (1.0, 1.25, 1.5, 2.0)


class UIModelError(ValueError):
    """Raised when a headless UI policy value is not canonical."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _digest(domain: bytes, value: Mapping[str, Any]) -> str:
    return hashlib.sha256(domain + _canonical(value)).hexdigest()


@dataclass(frozen=True)
class PageSpec:
    key: str
    title: str
    accessible_name: str
    purpose: str
    shortcut: str
    primary_action: str | None
    supports_pagination: bool
    network_dependent: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PAGE_SPECS: Final[tuple[PageSpec, ...]] = (
    PageSpec(
        "discover",
        "Discover",
        "Discover Guix packages",
        "Search the authenticated Guix package catalog and inspect package details.",
        "Ctrl+1",
        "Focus package search",
        True,
        True,
    ),
    PageSpec(
        "installed",
        "Installed",
        "Installed packages",
        "Review and remove packages from the explicitly selected per-user profile.",
        "Ctrl+2",
        "Refresh installed packages",
        True,
        False,
    ),
    PageSpec(
        "updates",
        "Updates",
        "Available package updates",
        "Preview and apply updates as a new reversible profile generation.",
        "Ctrl+3",
        "Check for updates",
        True,
        True,
    ),
    PageSpec(
        "generations",
        "Generations",
        "Profile generations",
        "Inspect, switch, roll back, and delete profile generations.",
        "Ctrl+4",
        "Refresh generations",
        True,
        False,
    ),
    PageSpec(
        "profiles",
        "Profiles",
        "Guix profile selection",
        "Select an isolated named user profile and explain its immutable generations.",
        "Ctrl+5",
        "Select profile",
        False,
        False,
    ),
    PageSpec(
        "channels-and-trust",
        "Channels & Trust",
        "Guix channels and trust",
        "Inspect channel provenance and execute pull only from a measured private snapshot.",
        "Ctrl+6",
        "Review channels",
        False,
        True,
    ),
    PageSpec(
        "storage",
        "Storage",
        "Guix storage management",
        "Preview garbage collection and review storage use before deletion.",
        "Ctrl+7",
        "Preview garbage collection",
        False,
        False,
    ),
    PageSpec(
        "activity",
        "Activity",
        "Authenticated Guix activity",
        "Review receipts only after exact log-byte authentication succeeds.",
        "Ctrl+8",
        "Refresh activity",
        True,
        False,
    ),
)

GLOBAL_SHORTCUTS: Final[tuple[dict[str, str], ...]] = (
    {"sequence": "Ctrl+K", "action": "Focus package search"},
    {"sequence": "Ctrl+R", "action": "Refresh current page"},
    {"sequence": "F6", "action": "Cycle primary regions"},
    {"sequence": "Shift+F6", "action": "Cycle primary regions backwards"},
    {"sequence": "Escape", "action": "Cancel active transaction or clear search"},
    {"sequence": "Ctrl+Q", "action": "Close Guix Center"},
)


def ui_model() -> dict[str, Any]:
    return {
        "format": FORMAT,
        "application_id": "co.securityops.GuixCenter",
        "toolkit": "Qt 6 / PySide 6",
        "pages": [page.to_dict() for page in PAGE_SPECS],
        "page_states": list(PAGE_STATES),
        "global_shortcuts": [dict(item) for item in GLOBAL_SHORTCUTS],
        "responsive_layout": {
            "minimum_width_px": 640,
            "minimum_height_px": 480,
            "compact_max_logical_width": 899,
            "regular_max_logical_width": 1439,
            "wide_min_logical_width": 1440,
            "supported_scale_factors": list(SCALE_FACTORS),
            "compact_sidebar": "condensed-labels",
            "regular_sidebar": "expanded",
            "compact_detail_pane_placement": "below-results",
            "regular_detail_pane_placement": "beside-results",
            "wide_detail_pane_placement": "beside-results",
        },
        "accessibility": {
            "unique_accessible_names_required": True,
            "keyboard_only_operation_required": True,
            "focus_order_manifest_required": True,
            "screen_reader_status_announcements_required": True,
            "error_messages_must_identify_recovery_action": True,
            "color_alone_may_convey_state": False,
            "reduced_motion_supported": True,
        },
        "truth_boundary": {
            "headless_snapshot_is_qt_runtime_evidence": False,
            "source_accessibility_manifest_is_screen_reader_evidence": False,
            "offscreen_smoke_is_interactive_session_evidence": False,
        },
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def validate_ui_model(value: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or value != ui_model():
        raise UIModelError("Guix Center UI model differs from the closed policy")
    names = [page["accessible_name"] for page in value["pages"]]
    shortcuts = [page["shortcut"] for page in value["pages"]]
    global_shortcuts = [item["sequence"] for item in value["global_shortcuts"]]
    if len(names) != len(set(names)):
        raise UIModelError("page accessible names must be unique")
    if len(shortcuts + global_shortcuts) != len(set(shortcuts + global_shortcuts)):
        raise UIModelError("keyboard shortcuts must be unique")
    return dict(value)


def ui_model_digest() -> str:
    model = ui_model()
    validate_ui_model(model)
    return _digest(DOMAIN, model)


def _canonical_dimension(name: str, value: int, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise UIModelError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _canonical_scale(scale: float) -> float:
    if type(scale) not in (int, float):
        raise UIModelError("scale factor must be numeric")
    canonical = float(scale)
    if canonical not in SCALE_FACTORS:
        raise UIModelError("scale factor is outside the validated HiDPI matrix")
    return canonical


def _canonical_states(states: Mapping[str, str] | None) -> dict[str, str]:
    result = {page.key: "ready" for page in PAGE_SPECS}
    if states is None:
        return result
    if type(states) is not dict or set(states) - set(result):
        raise UIModelError("page-state map contains an unknown page")
    for page, state in states.items():
        if state not in PAGE_STATES:
            raise UIModelError(f"invalid UI state for {page}")
        result[page] = state
    return result


def render_headless_snapshot(
    *,
    width_px: int,
    height_px: int,
    scale_factor: float,
    page_states: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a deterministic policy snapshot, never a Qt rendering claim."""
    width = _canonical_dimension("width", width_px, 640, 7680)
    height = _canonical_dimension("height", height_px, 480, 4320)
    scale = _canonical_scale(scale_factor)
    logical_width = width / scale
    if logical_width <= 899:
        layout = "compact"
        sidebar = "condensed-labels"
        detail_pane = True
        detail_placement = "below-results"
    elif logical_width <= 1439:
        layout = "regular"
        sidebar = "expanded"
        detail_pane = True
        detail_placement = "beside-results"
    else:
        layout = "wide"
        sidebar = "expanded"
        detail_pane = True
        detail_placement = "beside-results"
    states = _canonical_states(page_states)
    value: dict[str, Any] = {
        "format": SNAPSHOT_FORMAT,
        "ui_model_digest": ui_model_digest(),
        "viewport": {
            "width_px": width,
            "height_px": height,
            "scale_factor": scale,
            "logical_width": round(logical_width, 3),
        },
        "layout": {
            "mode": layout,
            "sidebar": sidebar,
            "detail_pane_visible": detail_pane,
            "detail_pane_placement": detail_placement,
        },
        "pages": [
            {
                "key": page.key,
                "title": page.title,
                "accessible_name": page.accessible_name,
                "shortcut": page.shortcut,
                "state": states[page.key],
            }
            for page in PAGE_SPECS
        ],
        "focus_order": [
            "global-navigation",
            "profile-selector",
            "page-primary-action",
            "page-content",
            "status-region",
        ],
        "headless_snapshot_is_qt_runtime_evidence": False,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }
    value["snapshot_digest"] = _digest(SNAPSHOT_DOMAIN, value)
    return value


def validate_headless_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "format",
        "ui_model_digest",
        "viewport",
        "layout",
        "pages",
        "focus_order",
        "headless_snapshot_is_qt_runtime_evidence",
        "production_dispatch_allowed",
        "iso_release_allowed",
        "snapshot_digest",
    }:
        raise UIModelError("headless UI snapshot has missing or unknown fields")
    expected = render_headless_snapshot(
        width_px=value.get("viewport", {}).get("width_px"),
        height_px=value.get("viewport", {}).get("height_px"),
        scale_factor=value.get("viewport", {}).get("scale_factor"),
        page_states={
            item["key"]: item["state"]
            for item in value.get("pages", [])
            if type(item) is dict and "key" in item and "state" in item
        },
    )
    if value != expected:
        raise UIModelError("headless UI snapshot differs from the deterministic model")
    return dict(value)


if __name__ == "__main__":
    print(json.dumps(ui_model(), sort_keys=True, indent=2))
