#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=81ca59d808f65a678fe464d6605aba6c owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Security Ops Guix Center — transactional GNU Guix package management GUI.

The graphical layer never accepts arbitrary command lines.  It asks the local
backend to construct exact Guix plans, previews every mutation, executes work in
background threads, and shows crash-safe receipts.  System reconfiguration and
root escalation are intentionally outside this application.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import threading
import time
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from guix_backend import (  # noqa: E402
    CatalogCache,
    DISABLED_ACTIONS,
    GC_DELETE_BLOCKER,
    PolicyError,
    TransactionPlan,
    admit_guix_executable,
    create_transaction_plan,
    discover_guix_candidates,
    guix_center_contract,
    guix_center_contract_digest,
    parse_guix_search_records,
    parse_installed_packages,
    parse_transaction_receipt,
    profile_path,
    validate_package_spec,
)
from phase37_guix_center import (  # noqa: E402
    ACCESSIBILITY_MANIFEST,
    OperationJournal,
    accessibility_manifest,
    capability_report,
    execute_transaction_plan_journaled,
    phase37_contract,
    phase37_contract_digest,
    phase37_selftest,
    validate_accessibility_snapshot,
)
from phase37_ui_model import (  # noqa: E402
    render_headless_snapshot,
    ui_model,
    ui_model_digest,
)

APP_NAME = "Security Ops Guix Center"
APP_ID = "co.securityops.GuixCenter"
VERSION = "0.2.0"
SEARCH_DEBOUNCE_MS = 250
PAGE_SIZE = 100
DEFAULT_PROFILES = ("default", "work", "development", "gaming")


def state_paths(home: Path) -> dict[str, Path]:
    state = home / ".local/state/securityops/guix-center"
    cache = home / ".cache/securityops/guix-center"
    return {
        "state": state,
        "cache": cache,
        "catalog": cache / "catalog.sqlite3",
        "settings": state / "ui-settings.json",
        "journal": state / "operation-journal",
    }


def secure_private_dir(path: Path) -> None:
    if not path.is_absolute():
        raise PolicyError("private state path must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise PolicyError(f"private state component is unsafe: {current}")
    final = path.lstat()
    if final.st_uid != os.geteuid():
        raise PolicyError("private state directory must be owned by the current user")
    if final.st_mode & 0o077:
        os.chmod(path, 0o700)


def atomic_settings(path: Path, value: dict[str, Any]) -> None:
    secure_private_dir(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def headless_contract() -> dict[str, Any]:
    contract = guix_center_contract()
    return {
        "format": "securityops-guix-center-headless/2",
        "name": APP_NAME,
        "version": VERSION,
        "application_id": APP_ID,
        "pages": contract["product"]["pages"],
        "toolkit": contract["product"]["toolkit"],
        "search_debounce_ms": SEARCH_DEBOUNCE_MS,
        "result_page_size": PAGE_SIZE,
        "transaction_preview_required": True,
        "exact_argv_review_required": True,
        "typed_confirmation_required_for_mutations": True,
        "per_user_profiles": True,
        "root_escalation_allowed": False,
        "system_reconfigure_available": False,
        "shell_allowed": False,
        "gnome_session_dependency_required": False,
        "contract_digest": guix_center_contract_digest(),
        "phase37_contract_digest": phase37_contract_digest(),
        "ui_model_digest": ui_model_digest(),
        "page_states": phase37_contract()["guix_center"]["page_states"],
        "accessibility_manifest": accessibility_manifest(),
        "descriptor_bound_guix_execution": True,
        "append_only_operation_journal": True,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def discover_admitted_guix(home: Path):
    errors: list[str] = []
    for candidate in discover_guix_candidates(home, home.name):
        try:
            return admit_guix_executable(candidate)
        except PolicyError as error:
            errors.append(f"{candidate}: {error}")
    return None, errors


def bounded_read(
    path: str,
    limit: int = 16 * 1024 * 1024,
    *,
    expected_sha256: str | None = None,
    expected_size: int | None = None,
) -> str:
    source = Path(path)
    descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise PolicyError("activity source must be a single-linked regular file")
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise PolicyError("activity source ownership or mode is unsafe")
        if metadata.st_size > limit:
            raise PolicyError("activity output exceeds the GUI display bound")
        if expected_size is not None and metadata.st_size != expected_size:
            raise PolicyError("activity output size differs from its receipt")
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            digest.update(block)
            remaining -= len(block)
        after = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise PolicyError("activity source changed during bounded read")
        if expected_sha256 is not None and digest.hexdigest() != expected_sha256:
            raise PolicyError("activity output digest differs from its receipt")
    finally:
        os.close(descriptor)
    return b"".join(chunks).decode("utf-8", errors="replace")


def run_gui(
    *, smoke_evidence: Path | None = None, smoke_width: int = 1320,
    smoke_height: int = 820, smoke_scale: float = 1.0,
) -> int:
    try:
        from PySide6.QtCore import QObject, QRunnable, QSize, Qt, QThreadPool, QTimer, Signal
        from PySide6.QtGui import QAction, QFont, QKeySequence
        from PySide6.QtWidgets import (
            QAbstractItemView,
            QApplication,
            QComboBox,
            QDialog,
            QDialogButtonBox,
            QFileDialog,
            QFormLayout,
            QFrame,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QListWidget,
            QListWidgetItem,
            QMainWindow,
            QMessageBox,
            QPushButton,
            QPlainTextEdit,
            QProgressBar,
            QScrollArea,
            QSizePolicy,
            QSplitter,
            QStackedWidget,
            QStatusBar,
            QTableWidget,
            QTableWidgetItem,
            QTextBrowser,
            QToolBar,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as error:
        print(
            "securityops-guix-center: PySide6 is unavailable; install the "
            "python-pyside-6 Guix package or use --headless-contract",
            file=sys.stderr,
        )
        return 2

    class WorkerSignals(QObject):
        completed = Signal(object)
        failed = Signal(str)

    class Worker(QRunnable):
        def __init__(self, fn: Callable[[], Any]) -> None:
            super().__init__()
            self.fn = fn
            self.signals = WorkerSignals()

        def run(self) -> None:
            try:
                self.signals.completed.emit(self.fn())
            except Exception as error:  # GUI boundary: render bounded message
                self.signals.failed.emit(str(error)[:8192])

    class TransactionDialog(QDialog):
        def __init__(self, plan: TransactionPlan, parent: QWidget | None = None) -> None:
            super().__init__(parent)
            self.setWindowTitle("Review Guix transaction")
            self.setModal(True)
            self.resize(760, 560)
            layout = QVBoxLayout(self)
            heading = QLabel("Review before applying")
            heading.setObjectName("dialogHeading")
            heading.setAccessibleName("Transaction review heading")
            layout.addWidget(heading)
            summary = QLabel(
                f"Action: {plan.action}   •   Profile: {plan.profile_name}   •   "
                f"Network: {'expected' if plan.network_expected else 'not expected'}"
            )
            summary.setWordWrap(True)
            layout.addWidget(summary)
            command = QPlainTextEdit()
            command.setReadOnly(True)
            command.setAccessibleName("Exact Guix command arguments")
            command.setPlainText(
                "Exact argument vector (no shell):\n\n"
                + "\n".join(f"[{index}] {item}" for index, item in enumerate(plan.argv))
                + f"\n\nPlan ID:\n{plan.plan_id}"
            )
            layout.addWidget(command, 1)
            channel_note = (
                " The selected channels file will be copied into a private measured snapshot "
                "before guix pull executes."
                if plan.action == "pull" else ""
            )
            warning = QLabel(
                "Guix creates a new profile generation when the action changes a profile. "
                "Rollback remains available. This application never requests sudo, pkexec, "
                "or system reconfigure." + channel_note
            )
            warning.setWordWrap(True)
            warning.setObjectName("warningText")
            layout.addWidget(warning)
            self.confirmation_phrase = f"APPLY {plan.plan_id[:12]}"
            confirmation_label = QLabel(
                "To prevent accidental changes, type the confirmation phrase exactly:\n"
                f"<b>{self.confirmation_phrase}</b>"
            )
            confirmation_label.setTextFormat(Qt.RichText)
            confirmation_label.setWordWrap(True)
            layout.addWidget(confirmation_label)
            self.confirmation_input = QLineEdit()
            self.confirmation_input.setAccessibleName("Typed transaction confirmation")
            self.confirmation_input.setPlaceholderText(self.confirmation_phrase)
            self.confirmation_input.setClearButtonEnabled(True)
            layout.addWidget(self.confirmation_input)
            buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
            apply_button = buttons.button(QDialogButtonBox.Ok)
            apply_button.setText("Apply transaction")
            apply_button.setEnabled(False)
            self.confirmation_input.textChanged.connect(
                lambda value: apply_button.setEnabled(value == self.confirmation_phrase)
            )
            buttons.accepted.connect(self.accept)
            buttons.rejected.connect(self.reject)
            layout.addWidget(buttons)

    class MainWindow(QMainWindow):
        PAGE_LABELS = {
            "discover": "Discover",
            "installed": "Installed",
            "updates": "Updates",
            "generations": "Generations",
            "profiles": "Profiles",
            "channels-and-trust": "Channels & trust",
            "storage": "Storage",
            "activity": "Activity",
        }

        def __init__(self) -> None:
            super().__init__()
            self.home = Path.home().resolve()
            self.paths = state_paths(self.home)
            secure_private_dir(self.paths["state"])
            secure_private_dir(self.paths["cache"])
            self.cache = CatalogCache(self.paths["catalog"])
            # Fail closed before presenting cached package metadata.  A corrupt,
            # substituted, or schema-drifted database must never be treated as
            # trusted catalog state merely because SQLite can open it.
            self.cache_integrity = self.cache.verify_integrity()
            self.journal = OperationJournal(self.paths["journal"])
            self.recovered_operations = self.journal.recover_interrupted(state_root=self.paths["state"])
            detected = discover_admitted_guix(self.home)
            if isinstance(detected, tuple):
                self.admitted = None
                self.discovery_errors = detected[1]
            else:
                self.admitted = detected
                self.discovery_errors = []
            self.pool = QThreadPool.globalInstance()
            self.pool.setMaxThreadCount(max(2, min(4, os.cpu_count() or 2)))
            self.busy_count = 0
            self.active_cancellations: dict[str, threading.Event] = {}
            self.page_widgets: dict[str, QWidget] = {}
            self.last_receipt: dict[str, Any] | None = None
            self.search_records: list[dict[str, Any]] = []
            self.installed_records: list[dict[str, Any]] = []
            self.setWindowTitle(f"{APP_NAME} — transactional GNU Guix")
            self.setMinimumSize(QSize(640, 480))
            self.resize(1320, 820)
            self._build_ui()
            self._apply_accessibility_contract()
            self._apply_responsive_layout()
            self._load_settings()
            self._refresh_runtime_status()
            self._show_cached_search("guix")

        def _semantic_widgets(self) -> dict[str, QWidget]:
            return {
                "discover-page": self.page_widgets["discover"],
                "installed-page": self.page_widgets["installed"],
                "updates-page": self.page_widgets["updates"],
                "generations-page": self.page_widgets["generations"],
                "profiles-page": self.page_widgets["profiles"],
                "channels-and-trust-page": self.page_widgets["channels-and-trust"],
                "storage-page": self.page_widgets["storage"],
                "activity-page": self.page_widgets["activity"],
                "package-search": self.search_input,
                "package-results": self.search_table,
                "package-details": self.package_detail,
                "install-selected-package": self.install_button,
                "installed-package-table": self.installed_table,
                "remove-selected-package": self.remove_button,
                "available-updates": self.updates_output,
                "apply-profile-upgrades": self.apply_updates_button,
                "generation-history": self.generations_output,
                "rollback-generation": self.rollback_button,
                "switch-generation": self.switch_generation_button,
                "delete-generations": self.delete_generations_button,
                "profile-selector": self.profile_combo,
                "profile-location": self.profile_path_display,
                "channels-file": self.channels_file,
                "channel-description": self.channels_output,
                "pull-channels": self.pull_channels_button,
                "gc-preview": self.gc_preview_button,
                "gc-delete": self.gc_delete_button,
                "transaction-activity": self.activity_table,
                "activity-output": self.activity_output,
                "cancel-active-transaction": self.cancel_button,
            }

        def _apply_accessibility_contract(self) -> None:
            semantic = self._semantic_widgets()
            expected = {
                identifier for values in ACCESSIBILITY_MANIFEST.values()
                for identifier in values
            }
            if set(semantic) != expected:
                raise PolicyError("Qt accessibility mapping differs from Phase 37")
            for identifier, widget in semantic.items():
                widget.setObjectName(identifier)
                if not widget.accessibleName().strip():
                    widget.setAccessibleName(identifier.replace("-", " ").title())

        def accessibility_snapshot(self, *, scale_factor: float = 1.0) -> dict[str, Any]:
            semantic = self._semantic_widgets()
            widgets = []
            for identifier in sorted(semantic):
                widget = semantic[identifier]
                widgets.append({
                    "id": identifier,
                    "accessible_name": widget.accessibleName().strip(),
                    "visible": bool(widget.isVisible()),
                    "enabled": bool(widget.isEnabled()),
                    "class": widget.metaObject().className(),
                })
            width = int(self.width())
            height = int(self.height())
            logical_width = round(width / float(scale_factor), 3)
            layout = "compact" if logical_width <= 899 else (
                "regular" if logical_width <= 1439 else "wide"
            )
            return validate_accessibility_snapshot({
                "format": "securityops-phase37-qt-accessibility-snapshot/1",
                "toolkit": "Qt 6 / PySide 6",
                "application_id": APP_ID,
                "widgets": widgets,
                "page_count": len(self.page_widgets),
                "viewport": {
                    "width_px": width,
                    "height_px": height,
                    "scale_factor": float(scale_factor),
                    "logical_width": logical_width,
                    "layout": layout,
                },
                "production_dispatch_allowed": False,
                "iso_release_allowed": False,
            })

        def _apply_responsive_layout(self, width: int | None = None) -> None:
            """Keep one Qt UI usable from 640px through HiDPI widescreen."""
            if not hasattr(self, "sidebar"):
                return
            effective_width = self.width() if width is None else width
            compact = effective_width < 900
            self.sidebar.setFixedWidth(150 if compact else 230)
            labels = {
                "discover": "Discover",
                "installed": "Installed",
                "updates": "Updates",
                "generations": "History" if compact else "Generations",
                "profiles": "Profiles",
                "channels-and-trust": "Trust" if compact else "Channels & trust",
                "storage": "Storage",
                "activity": "Activity",
            }
            for row in range(self.sidebar.count()):
                item = self.sidebar.item(row)
                item.setText(labels[str(item.data(Qt.UserRole))])
            self.profile_combo.setMinimumWidth(120 if compact else 190)
            self.profile_combo.setMaximumWidth(160 if compact else 320)
            self.cancel_button.setText("Cancel" if compact else "Cancel transaction")
            if hasattr(self, "discover_splitter"):
                self.discover_splitter.setOrientation(
                    Qt.Vertical if compact else Qt.Horizontal
                )
                self.discover_splitter.setSizes(
                    (420, 280) if compact else (760, 380)
                )

        def resizeEvent(self, event) -> None:  # type: ignore[override]
            self._apply_responsive_layout(event.size().width())
            super().resizeEvent(event)

        def _select_page(self, row: int) -> None:
            if 0 <= row < self.sidebar.count():
                self.sidebar.setCurrentRow(row)
                self.sidebar.setFocus()

        def _escape_action(self) -> None:
            if self.active_cancellations:
                self._cancel_active_transactions()
            elif self.search_input.text():
                self.search_input.clear()
                self.search_input.setFocus()

        def _cycle_primary_region(self, *, reverse: bool = False) -> None:
            regions = (self.sidebar, self.search_input, self.stack, self.profile_combo)
            focused = self.focusWidget()
            try:
                index = regions.index(focused)
            except ValueError:
                index = 0 if reverse else -1
            step = -1 if reverse else 1
            regions[(index + step) % len(regions)].setFocus()

        def closeEvent(self, event) -> None:  # type: ignore[override]
            if self.busy_count > 0:
                QMessageBox.information(
                    self, APP_NAME,
                    "A Guix transaction is still running. Use Cancel transaction or wait for "
                    "bounded worker cleanup so its authenticated receipt remains complete.",
                )
                event.ignore()
                return
            self._save_settings()
            self.cache.close()
            super().closeEvent(event)

        def _build_ui(self) -> None:
            toolbar = QToolBar("Main toolbar")
            toolbar.setMovable(False)
            toolbar.setIconSize(QSize(18, 18))
            self.addToolBar(toolbar)
            brand = QLabel("  SECURITY OPS  /  GUIX CENTER  ")
            brand.setObjectName("brand")
            toolbar.addWidget(brand)
            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            toolbar.addWidget(spacer)
            profile_label = QLabel("Profile")
            profile_label.setAccessibleName("Selected Guix profile")
            toolbar.addWidget(profile_label)
            self.profile_combo = QComboBox()
            self.profile_combo.setEditable(True)
            self.profile_combo.setMinimumWidth(190)
            self.profile_combo.addItems(DEFAULT_PROFILES)
            self.profile_combo.setAccessibleName("Guix profile selector")
            self.profile_combo.setObjectName("profile-selector")
            self.profile_combo.currentTextChanged.connect(self._profile_changed)
            toolbar.addWidget(self.profile_combo)
            refresh_action = QAction("Refresh", self)
            refresh_action.setShortcut(QKeySequence.Refresh)
            refresh_action.triggered.connect(self.refresh_current_page)
            toolbar.addAction(refresh_action)
            self.cancel_button = QPushButton("Cancel transaction")
            self.cancel_button.setObjectName("cancel-active-transaction")
            self.cancel_button.setAccessibleName("Cancel active Guix transaction")
            self.cancel_button.setToolTip(
                "Request bounded cancellation of active Guix transactions"
            )
            self.cancel_button.setEnabled(False)
            self.cancel_button.clicked.connect(self._cancel_active_transactions)
            toolbar.addWidget(self.cancel_button)

            central = QWidget()
            root = QHBoxLayout(central)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)
            self.sidebar = QListWidget()
            self.sidebar.setObjectName("sidebar")
            self.sidebar.setFixedWidth(230)
            self.sidebar.setAccessibleName("Guix Center sections")
            for key in guix_center_contract()["product"]["pages"]:
                item = QListWidgetItem(self.PAGE_LABELS[key])
                item.setData(Qt.UserRole, key)
                item.setToolTip(self._page_tooltip(key))
                self.sidebar.addItem(item)
            self.sidebar.currentRowChanged.connect(self._page_changed)
            root.addWidget(self.sidebar)
            self.stack = QStackedWidget()
            root.addWidget(self.stack, 1)
            self.setCentralWidget(central)

            builders = {
                "discover": self._build_discover_page,
                "installed": self._build_installed_page,
                "updates": self._build_updates_page,
                "generations": self._build_generations_page,
                "profiles": self._build_profiles_page,
                "channels-and-trust": self._build_channels_page,
                "storage": self._build_storage_page,
                "activity": self._build_activity_page,
            }
            for key in guix_center_contract()["product"]["pages"]:
                page = builders[key]()
                page.setObjectName(f"{key}-page")
                page.setAccessibleName(f"{self.PAGE_LABELS[key]} page")
                self.page_widgets[key] = page
                self.stack.addWidget(page)
            self.sidebar.setCurrentRow(0)

            status = QStatusBar()
            self.runtime_label = QLabel()
            self.runtime_label.setAccessibleName("Guix runtime status")
            status.addWidget(self.runtime_label, 1)
            self.progress = QProgressBar()
            self.progress.setRange(0, 0)
            self.progress.setMaximumWidth(180)
            self.progress.hide()
            status.addPermanentWidget(self.progress)
            self.setStatusBar(status)

            focus_search = QAction("Focus package search", self)
            focus_search.setShortcut(QKeySequence("Ctrl+K"))
            focus_search.triggered.connect(lambda: self.search_input.setFocus())
            self.addAction(focus_search)

            refresh_shortcut = QAction("Refresh current page", self)
            refresh_shortcut.setShortcut(QKeySequence("Ctrl+R"))
            refresh_shortcut.triggered.connect(self.refresh_current_page)
            self.addAction(refresh_shortcut)

            for row in range(self.sidebar.count()):
                page_action = QAction(f"Open page {row + 1}", self)
                page_action.setShortcut(QKeySequence(f"Ctrl+{row + 1}"))
                page_action.triggered.connect(
                    lambda _checked=False, selected=row: self._select_page(selected)
                )
                self.addAction(page_action)

            escape_action = QAction("Cancel transaction or clear search", self)
            escape_action.setShortcut(QKeySequence("Escape"))
            escape_action.triggered.connect(self._escape_action)
            self.addAction(escape_action)

            focus_forward = QAction("Cycle primary regions", self)
            focus_forward.setShortcut(QKeySequence("F6"))
            focus_forward.triggered.connect(self._cycle_primary_region)
            self.addAction(focus_forward)

            focus_backward = QAction("Cycle primary regions backwards", self)
            focus_backward.setShortcut(QKeySequence("Shift+F6"))
            focus_backward.triggered.connect(
                lambda: self._cycle_primary_region(reverse=True)
            )
            self.addAction(focus_backward)

            close_action = QAction("Close Guix Center", self)
            close_action.setShortcut(QKeySequence("Ctrl+Q"))
            close_action.triggered.connect(self.close)
            self.addAction(close_action)

        @staticmethod
        def _page_tooltip(key: str) -> str:
            return {
                "discover": "Search packages and review details",
                "installed": "Packages in the selected per-user profile",
                "updates": "Available profile upgrades",
                "generations": "History, rollback and generation switching",
                "profiles": "Choose isolated per-user profiles",
                "channels-and-trust": "Inspect channel provenance and pull explicitly",
                "storage": "Preview and run garbage collection",
                "activity": "Crash-safe transaction receipts and logs",
            }[key]

        def _page_shell(self, title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(30, 26, 30, 26)
            layout.setSpacing(14)
            heading = QLabel(title)
            heading.setObjectName("pageHeading")
            heading.setAccessibleName(f"{title} page")
            layout.addWidget(heading)
            text = QLabel(subtitle)
            text.setWordWrap(True)
            text.setObjectName("pageSubtitle")
            layout.addWidget(text)
            return page, layout

        def _build_discover_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Discover packages",
                "Search the local catalog instantly, then refresh matching records from the admitted Guix executable.",
            )
            bar = QHBoxLayout()
            self.search_input = QLineEdit()
            self.search_input.setPlaceholderText("Search by package name or purpose…")
            self.search_input.setClearButtonEnabled(True)
            self.search_input.setAccessibleName("Package search")
            self.search_input.setObjectName("package-search")
            self.search_input.setToolTip("Search is debounced by 250 milliseconds")
            bar.addWidget(self.search_input, 1)
            self.online_search_button = QPushButton("Refresh from Guix")
            self.online_search_button.clicked.connect(self._online_search)
            bar.addWidget(self.online_search_button)
            layout.addLayout(bar)
            self.cache_age_label = QLabel("Catalog cache has not been refreshed yet")
            self.cache_age_label.setObjectName("muted")
            layout.addWidget(self.cache_age_label)

            splitter = QSplitter(Qt.Horizontal)
            self.discover_splitter = splitter
            self.search_table = QTableWidget(0, 4)
            self.search_table.setHorizontalHeaderLabels(("Package", "Version", "Output", "Summary"))
            self.search_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.search_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.search_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.search_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
            self.search_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.search_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.search_table.setAlternatingRowColors(True)
            self.search_table.setAccessibleName("Package search results")
            self.search_table.setObjectName("package-results")
            self.search_table.itemSelectionChanged.connect(self._show_selected_package)
            splitter.addWidget(self.search_table)
            detail = QWidget()
            detail_layout = QVBoxLayout(detail)
            self.package_title = QLabel("Select a package")
            self.package_title.setObjectName("detailHeading")
            detail_layout.addWidget(self.package_title)
            self.package_detail = QTextBrowser()
            self.package_detail.setOpenExternalLinks(False)
            self.package_detail.setAccessibleName("Selected package details")
            self.package_detail.setObjectName("package-details")
            detail_layout.addWidget(self.package_detail, 1)
            self.install_button = QPushButton("Install in selected profile")
            self.install_button.setObjectName("install-selected-package")
            self.install_button.setAccessibleName("Install selected package")
            self.install_button.setEnabled(False)
            self.install_button.clicked.connect(self._install_selected)
            detail_layout.addWidget(self.install_button)
            splitter.addWidget(detail)
            splitter.setSizes((760, 380))
            layout.addWidget(splitter, 1)

            self.search_timer = QTimer(self)
            self.search_timer.setSingleShot(True)
            self.search_timer.setInterval(SEARCH_DEBOUNCE_MS)
            self.search_timer.timeout.connect(lambda: self._show_cached_search(self.search_input.text()))
            self.search_input.textChanged.connect(lambda _text: self.search_timer.start())
            return page

        def _build_installed_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Installed packages",
                "This view is scoped to the selected per-user profile; system reconfiguration is never performed here.",
            )
            row = QHBoxLayout()
            button = QPushButton("Refresh installed packages")
            button.clicked.connect(self._refresh_installed)
            row.addWidget(button)
            self.remove_button = QPushButton("Remove selected")
            self.remove_button.setObjectName("remove-selected-package")
            self.remove_button.setAccessibleName("Remove selected package")
            self.remove_button.setEnabled(False)
            self.remove_button.clicked.connect(self._remove_selected)
            row.addWidget(self.remove_button)
            row.addStretch(1)
            layout.addLayout(row)
            self.installed_table = QTableWidget(0, 4)
            self.installed_table.setHorizontalHeaderLabels(("Package", "Version", "Output", "Store path"))
            self.installed_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.installed_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.installed_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.installed_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
            self.installed_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.installed_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.installed_table.setAccessibleName("Installed packages")
            self.installed_table.setObjectName("installed-package-table")
            self.installed_table.itemSelectionChanged.connect(
                lambda: self.remove_button.setEnabled(bool(self.installed_table.selectedItems()))
            )
            layout.addWidget(self.installed_table, 1)
            return page

        def _build_updates_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Updates",
                "Check available upgrades first. Applying updates creates a new Guix profile generation that can be rolled back.",
            )
            row = QHBoxLayout()
            check = QPushButton("Check for updates")
            check.clicked.connect(self._check_updates)
            row.addWidget(check)
            self.apply_updates_button = QPushButton("Upgrade selected profile")
            self.apply_updates_button.setObjectName("apply-profile-upgrades")
            self.apply_updates_button.setAccessibleName("Apply profile upgrades")
            self.apply_updates_button.clicked.connect(lambda: self._submit_plan("upgrade"))
            row.addWidget(self.apply_updates_button)
            row.addStretch(1)
            layout.addLayout(row)
            self.updates_output = QPlainTextEdit()
            self.updates_output.setReadOnly(True)
            self.updates_output.setAccessibleName("Available Guix updates")
            self.updates_output.setObjectName("available-updates")
            self.updates_output.setPlaceholderText("No update check has run yet.")
            layout.addWidget(self.updates_output, 1)
            return page

        def _build_generations_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Generations",
                "Inspect immutable profile history, roll back one generation, or switch to a specific known generation.",
            )
            row = QHBoxLayout()
            refresh = QPushButton("Refresh generations")
            refresh.clicked.connect(self._refresh_generations)
            row.addWidget(refresh)
            self.rollback_button = QPushButton("Roll back")
            self.rollback_button.setObjectName("rollback-generation")
            self.rollback_button.setAccessibleName("Rollback generation")
            self.rollback_button.clicked.connect(lambda: self._submit_plan("rollback"))
            row.addWidget(self.rollback_button)
            self.switch_generation_button = QPushButton("Switch generation…")
            self.switch_generation_button.setObjectName("switch-generation")
            self.switch_generation_button.setAccessibleName("Switch generation")
            self.switch_generation_button.clicked.connect(self._switch_generation)
            row.addWidget(self.switch_generation_button)
            self.delete_generations_button = QPushButton("Delete old generations…")
            self.delete_generations_button.setObjectName("delete-generations")
            self.delete_generations_button.setAccessibleName("Delete generations")
            self.delete_generations_button.clicked.connect(self._delete_generations)
            row.addWidget(self.delete_generations_button)
            row.addStretch(1)
            layout.addLayout(row)
            self.generations_output = QPlainTextEdit()
            self.generations_output.setReadOnly(True)
            self.generations_output.setAccessibleName("Guix profile generation history")
            self.generations_output.setObjectName("generation-history")
            layout.addWidget(self.generations_output, 1)
            return page

        def _build_profiles_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Profiles",
                "Profiles isolate package sets for work, development, gaming, or experiments without modifying the operating system.",
            )
            card = QFrame()
            card.setObjectName("card")
            form = QFormLayout(card)
            self.profile_name_display = QLabel(self.current_profile())
            self.profile_path_display = QLabel(str(profile_path(self.home, self.current_profile())))
            self.profile_path_display.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.profile_path_display.setObjectName("profile-location")
            self.profile_path_display.setAccessibleName("Selected profile location")
            form.addRow("Selected profile", self.profile_name_display)
            form.addRow("Profile path", self.profile_path_display)
            form.addRow("Privilege model", QLabel("Per-user only — no sudo, pkexec, or root"))
            form.addRow("Transactions", QLabel("Serialized per profile with atomic receipts"))
            layout.addWidget(card)
            guidance = QTextBrowser()
            guidance.setHtml(
                "<h3>For users coming from other distributions</h3>"
                "<p>A Guix profile is similar to an isolated package environment, but every change "
                "creates a generation. Use <b>default</b> for everyday applications and named "
                "profiles for separate workflows. Removing a package never edits the base OS.</p>"
                "<p>The first install into a named profile creates it automatically. You can switch "
                "back through the Generations page.</p>"
            )
            guidance.setAccessibleName("GNU Guix profile onboarding")
            layout.addWidget(guidance, 1)
            return page

        def _build_channels_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Channels & trust",
                "Inspect the exact channel graph and explicitly choose an owned channels file before pulling updates.",
            )
            row = QHBoxLayout()
            describe = QPushButton("Describe current channels")
            describe.clicked.connect(lambda: self._submit_plan("describe"))
            row.addWidget(describe)
            self.channels_file = QLineEdit(str(self.home / ".config/guix/channels.scm"))
            self.channels_file.setAccessibleName("Explicit channels file")
            self.channels_file.setObjectName("channels-file")
            row.addWidget(self.channels_file, 1)
            browse = QPushButton("Browse…")
            browse.clicked.connect(self._browse_channels)
            row.addWidget(browse)
            self.pull_channels_button = QPushButton("Pull channels")
            self.pull_channels_button.setObjectName("pull-channels")
            self.pull_channels_button.setAccessibleName("Pull channels")
            self.pull_channels_button.clicked.connect(self._pull_channels)
            row.addWidget(self.pull_channels_button)
            layout.addLayout(row)
            self.channels_output = QPlainTextEdit()
            self.channels_output.setReadOnly(True)
            self.channels_output.setAccessibleName("Channel and trust details")
            self.channels_output.setObjectName("channel-description")
            self.channels_output.setPlaceholderText(
                "Channel metadata will appear here. Pull uses only the selected owner-controlled file."
            )
            layout.addWidget(self.channels_output, 1)
            return page

        def _build_storage_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Storage",
                "List objects currently unreachable in the shared Guix Store. "
                "This staleable inventory is not scoped to the selected profile and never authorizes deletion.",
            )
            row = QHBoxLayout()
            self.gc_preview_button = QPushButton("Preview garbage collection")
            self.gc_preview_button.setObjectName("gc-preview")
            self.gc_preview_button.setAccessibleName("Preview garbage collection")
            self.gc_preview_button.clicked.connect(lambda: self._submit_plan("gc-dry-run"))
            row.addWidget(self.gc_preview_button)
            self.gc_delete_button = QPushButton("Delete unreachable store objects")
            self.gc_delete_button.setObjectName("gc-delete")
            self.gc_delete_button.setAccessibleName("Delete unreachable store objects")
            self.gc_delete_button.setAccessibleDescription(GC_DELETE_BLOCKER)
            self.gc_delete_button.setToolTip(GC_DELETE_BLOCKER)
            self.gc_delete_button.setEnabled(False)
            self.gc_delete_button.setFocusPolicy(Qt.NoFocus)
            row.addWidget(self.gc_delete_button)
            row.addStretch(1)
            layout.addLayout(row)
            self.storage_output = QPlainTextEdit()
            self.storage_output.setReadOnly(True)
            self.storage_output.setAccessibleName("Guix storage operation output")
            layout.addWidget(self.storage_output, 1)
            return page

        def _build_activity_page(self) -> QWidget:
            page, layout = self._page_shell(
                "Activity",
                "Every attempted transaction produces bounded logs and a mode-0600 receipt under your user state directory.",
            )
            row = QHBoxLayout()
            refresh = QPushButton("Refresh activity")
            refresh.clicked.connect(self._refresh_activity)
            row.addWidget(refresh)
            row.addStretch(1)
            layout.addLayout(row)
            self.activity_table = QTableWidget(0, 6)
            self.activity_table.setHorizontalHeaderLabels(
                ("Finished", "Action", "Profile", "Result", "Output", "Plan ID")
            )
            self.activity_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            self.activity_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self.activity_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            self.activity_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            self.activity_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
            self.activity_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
            self.activity_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self.activity_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
            self.activity_table.setAccessibleName("Guix transaction activity")
            self.activity_table.setObjectName("transaction-activity")
            self.activity_table.cellDoubleClicked.connect(self._open_activity_row)
            layout.addWidget(self.activity_table, 1)
            self.activity_output = QPlainTextEdit()
            self.activity_output.setReadOnly(True)
            self.activity_output.setObjectName("activity-output")
            self.activity_output.setAccessibleName("Authenticated activity output")
            self.activity_output.setMaximumHeight(150)
            self.activity_output.setPlaceholderText(
                "Open an authenticated transaction to inspect its bounded output."
            )
            layout.addWidget(self.activity_output)
            return page

        def _page_changed(self, row: int) -> None:
            if row >= 0:
                self.stack.setCurrentIndex(row)
                self.refresh_current_page(passive=True)

        def current_page(self) -> str:
            item = self.sidebar.currentItem()
            return str(item.data(Qt.UserRole)) if item else "discover"

        def current_profile(self) -> str:
            value = self.profile_combo.currentText().strip()
            profile_path(self.home, value)
            return value

        def _profile_changed(self, _value: str) -> None:
            try:
                profile = self.current_profile()
                resolved = str(profile_path(self.home, profile))
            except PolicyError as error:
                if hasattr(self, "profile_name_display"):
                    self.profile_name_display.setText("Invalid profile name")
                    self.profile_path_display.setText("No transaction will be created")
                self.statusBar().showMessage(str(error), 5000)
                return
            if hasattr(self, "profile_name_display"):
                self.profile_name_display.setText(profile)
                self.profile_path_display.setText(resolved)
            self.statusBar().showMessage(f"Selected profile: {profile}", 3000)

        def _refresh_runtime_status(self) -> None:
            if self.admitted is None:
                self.runtime_label.setText("Guix runtime not admitted — cached browsing remains available")
                self.online_search_button.setEnabled(False)
                detail = "\n".join(self.discovery_errors[-3:])
                self.runtime_label.setToolTip(detail)
            else:
                marker = self.admitted.sha256[:12]
                self.runtime_label.setText(
                    f"Admitted Guix: {self.admitted.resolved_path}  •  sha256 {marker}…"
                )
                self.online_search_button.setEnabled(True)

        def refresh_current_page(self, passive: bool = False) -> None:
            page = self.current_page()
            actions = {
                "installed": self._refresh_installed,
                "updates": self._check_updates,
                "generations": self._refresh_generations,
                "activity": self._refresh_activity,
            }
            if page in actions and (not passive or page == "activity"):
                actions[page]()

        def _show_cached_search(self, query: str) -> None:
            clean = query.strip()
            if not clean:
                self._populate_search([])
                return
            try:
                records = self.cache.search(clean, limit=PAGE_SIZE)
            except PolicyError as error:
                self.statusBar().showMessage(str(error), 5000)
                return
            self.search_records = records
            self._populate_search(records)
            updated = self.cache.updated_unix()
            if updated is None:
                self.cache_age_label.setText("No cached catalog data; refresh from Guix when available")
            else:
                timestamp = datetime.fromtimestamp(updated, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                age = max(0, int(time.time()) - updated)
                stale = " • stale" if age > 24 * 60 * 60 else ""
                self.cache_age_label.setText(f"Local catalog updated {timestamp}{stale}")

        def _populate_search(self, records: list[dict[str, Any]]) -> None:
            self.search_table.setRowCount(len(records))
            for row, record in enumerate(records):
                values = (
                    str(record.get("name", "")),
                    str(record.get("version", "")),
                    str(record.get("output", "out")),
                    str(record.get("synopsis", "")),
                )
                for column, value in enumerate(values):
                    self.search_table.setItem(row, column, QTableWidgetItem(value))
            if records:
                self.search_table.selectRow(0)
            else:
                self.package_title.setText("No matching packages")
                self.package_detail.clear()
                self.install_button.setEnabled(False)

        def _show_selected_package(self) -> None:
            row = self.search_table.currentRow()
            if row < 0 or row >= len(self.search_records):
                self.install_button.setEnabled(False)
                return
            record = self.search_records[row]
            name = str(record.get("name", ""))
            version = str(record.get("version", ""))
            output = str(record.get("output", "out"))
            self.package_title.setText(f"{name}  {version}")
            synopsis = html.escape(str(record.get("synopsis", "")))
            description = html.escape(str(record.get("description", ""))).replace("\n", "<br>")
            location = html.escape(str(record.get("location", "")))
            self.package_detail.setHtml(
                f"<p><b>Output:</b> {html.escape(output)}</p>"
                f"<p>{synopsis}</p><p>{description}</p><p><small>{location}</small></p>"
            )
            self.install_button.setEnabled(self.admitted is not None)

        def _online_search(self) -> None:
            query = self.search_input.text().strip()
            if not query:
                self.statusBar().showMessage("Enter a package search query", 4000)
                return
            self._submit_plan("search", query=query)

        def _selected_search_spec(self) -> str | None:
            row = self.search_table.currentRow()
            if row < 0 or row >= len(self.search_records):
                return None
            record = self.search_records[row]
            base = str(record.get("name", ""))
            version = str(record.get("version", ""))
            output = str(record.get("output", "out"))
            return validate_package_spec(f"{base}@{version}:{output}")

        def _install_selected(self) -> None:
            specification = self._selected_search_spec()
            if specification:
                self._submit_plan("install", package_specs=(specification,))

        def _refresh_installed(self) -> None:
            self._submit_plan("list-installed")

        def _remove_selected(self) -> None:
            row = self.installed_table.currentRow()
            if row < 0 or row >= len(self.installed_records):
                return
            record = self.installed_records[row]
            specification = validate_package_spec(
                f"{record['name']}@{record['version']}:{record['output']}"
            )
            self._submit_plan("remove", package_specs=(specification,))

        def _check_updates(self) -> None:
            self._submit_plan("list-upgrades")

        def _refresh_generations(self) -> None:
            self._submit_plan("list-generations")

        def _switch_generation(self) -> None:
            from PySide6.QtWidgets import QInputDialog
            value, accepted = QInputDialog.getInt(
                self, "Switch generation", "Generation number", 1, 1, 2**31 - 1, 1
            )
            if accepted:
                self._submit_plan("switch-generation", generation=value)

        def _delete_generations(self) -> None:
            from PySide6.QtWidgets import QInputDialog
            value, accepted = QInputDialog.getText(
                self,
                "Delete old generations",
                "Selector (example: 30d, 6m, 2-5, or 7)",
            )
            if accepted and value.strip():
                self._submit_plan("delete-generations", delete_generations=value.strip())

        def _browse_channels(self) -> None:
            selected, _filter = QFileDialog.getOpenFileName(
                self, "Select channels.scm", str(self.home / ".config/guix"), "Scheme (*.scm);;All files (*)"
            )
            if selected:
                self.channels_file.setText(selected)

        def _pull_channels(self) -> None:
            self._submit_plan("pull", channels_file=Path(self.channels_file.text()))

        def _make_plan(self, action: str, **kwargs: Any) -> TransactionPlan:
            if self.admitted is None:
                raise PolicyError(
                    "No immutable Guix executable was admitted. Install GNU Guix for your user "
                    "or boot Security Ops OS, then reopen the application."
                )
            channels_file = kwargs.pop("channels_file", None)
            return create_transaction_plan(
                admitted=self.admitted,
                home=self.home,
                profile=self.current_profile(),
                action=action,
                channels_file=channels_file,
                owner_uid=os.getuid() if channels_file is not None else None,
                timeout_seconds=3600,
                **kwargs,
            )

        def _submit_plan(self, action: str, **kwargs: Any) -> None:
            if action in DISABLED_ACTIONS:
                self._error(GC_DELETE_BLOCKER)
                return
            try:
                plan = self._make_plan(action, **kwargs)
            except Exception as error:
                self._error(str(error))
                return
            confirmation: str | None = None
            if plan.confirmation_required:
                dialog = TransactionDialog(plan, self)
                if dialog.exec() != QDialog.Accepted:
                    return
                confirmation = plan.plan_id
            cancellation = threading.Event()
            self.active_cancellations[plan.operation_nonce] = cancellation
            self._set_busy(True, f"Running {action} for profile {plan.profile_name}…")
            worker = Worker(
                lambda: execute_transaction_plan_journaled(
                    plan,
                    home=self.home,
                    state_root=self.paths["state"],
                    confirmation_plan_id=confirmation,
                    cancel_event=cancellation,
                )
            )
            worker.signals.completed.connect(
                lambda receipt: self._transaction_completed(plan, receipt)
            )
            worker.signals.failed.connect(
                lambda message: self._transaction_failed(plan.operation_nonce, message)
            )
            self.pool.start(worker)

        def _cancel_active_transactions(self) -> None:
            if not self.active_cancellations:
                return
            for event in self.active_cancellations.values():
                event.set()
            self.cancel_button.setEnabled(False)
            self.statusBar().showMessage(
                "Cancellation requested. Waiting for bounded worker cleanup and receipt publication…"
            )

        def _forget_operation(self, operation_id: str) -> None:
            self.active_cancellations.pop(operation_id, None)
            self.cancel_button.setEnabled(bool(self.active_cancellations))

        def _set_busy(self, busy: bool, message: str = "") -> None:
            self.busy_count = max(0, self.busy_count + (1 if busy else -1))
            self.progress.setVisible(self.busy_count > 0)
            self.cancel_button.setEnabled(bool(self.active_cancellations))
            if message:
                self.statusBar().showMessage(message)

        def _transaction_failed(self, operation_id: str, message: str) -> None:
            self._forget_operation(operation_id)
            self._set_busy(False)
            self._error(message)

        def _transaction_completed(self, plan: TransactionPlan, receipt: dict[str, Any]) -> None:
            self._forget_operation(plan.operation_nonce)
            self._set_busy(False)
            try:
                # Authenticate the closed receipt and its exact stdout/stderr bytes
                # before the UI displays, parses, caches, or acts on any result.
                receipt = parse_transaction_receipt(
                    receipt, state_root=self.paths["state"]
                )
                stdout = bounded_read(
                    receipt["stdout_path"],
                    expected_sha256=receipt["stdout_sha256"],
                    expected_size=receipt["stdout_bytes"],
                )
                stderr = bounded_read(
                    receipt["stderr_path"],
                    expected_sha256=receipt["stderr_sha256"],
                    expected_size=receipt["stderr_bytes"],
                )
            except Exception as error:
                self._error(
                    "Authenticated receipt or activity log verification failed. "
                    "The transaction result will not be displayed, parsed, or cached.\n\n"
                    + str(error)
                )
                self._refresh_activity()
                return
            self.last_receipt = receipt
            combined = stdout + ("\n" + stderr if stderr else "")
            if not receipt.get("success"):
                self._error(
                    f"Guix action {plan.action} failed with return code {receipt.get('returncode')}.\n\n"
                    + combined[-6000:]
                )
            else:
                self.statusBar().showMessage(
                    f"Completed {plan.action} for profile {plan.profile_name}", 6000
                )
            try:
                self._route_output(plan, stdout, stderr, receipt)
            finally:
                self._refresh_activity()

        def _route_output(
            self,
            plan: TransactionPlan,
            stdout: str,
            stderr: str,
            receipt: dict[str, Any],
        ) -> None:
            text = stdout + ("\n" + stderr if stderr else "")
            if plan.action == "search" and receipt.get("success"):
                records = parse_guix_search_records(stdout)
                self.cache.upsert_packages(records, updated_unix=int(time.time()))
                self.cache.checkpoint()
                self.cache.verify_integrity()
                self.search_records = records
                self._populate_search(records)
                self._show_cached_search(plan.query or "")
            elif plan.action == "list-installed" and receipt.get("success"):
                self.installed_records = parse_installed_packages(stdout)
                self.installed_table.setRowCount(len(self.installed_records))
                for row, record in enumerate(self.installed_records):
                    for column, key in enumerate(("name", "version", "output", "path")):
                        self.installed_table.setItem(row, column, QTableWidgetItem(record[key]))
            elif plan.action == "list-upgrades":
                self.updates_output.setPlainText(text)
            elif plan.action == "list-generations":
                self.generations_output.setPlainText(text)
            elif plan.action == "describe" or plan.action == "pull":
                self.channels_output.setPlainText(text)
            elif plan.action.startswith("gc-"):
                self.storage_output.setPlainText(text)
            elif plan.mutating and receipt.get("success"):
                if plan.action in {"install", "remove", "upgrade"}:
                    self._refresh_installed()
                if plan.action in {"rollback", "switch-generation", "delete-generations"}:
                    self._refresh_generations()

        def _refresh_activity(self) -> None:
            receipt_dir = self.paths["state"] / "receipts"
            records: list[dict[str, Any]] = []
            if receipt_dir.is_dir() and not receipt_dir.is_symlink():
                for path in sorted(receipt_dir.glob("*.json"), reverse=True)[:500]:
                    try:
                        if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                            continue
                        raw = json.loads(bounded_read(str(path), 2 * 1024 * 1024))
                        records.append(parse_transaction_receipt(raw, state_root=self.paths["state"]))
                    except (OSError, ValueError, json.JSONDecodeError, PolicyError):
                        continue
            records.sort(
                key=lambda item: (int(item.get("finished_unix", 0)), str(item.get("plan_id", ""))),
                reverse=True,
            )
            self.activity_records = records
            self.activity_table.setRowCount(len(records))
            for row, record in enumerate(records):
                finished = int(record.get("finished_unix", 0))
                timestamp = datetime.fromtimestamp(finished, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if finished else "—"
                action = str(record.get("action", ""))
                action_label = (
                    f"{action} (historical — action disabled)"
                    if action in DISABLED_ACTIONS else action
                )
                values = (
                    timestamp,
                    action_label,
                    str(record.get("profile_name", "")),
                    "Success" if record.get("success") else "Failed",
                    f"{record.get('stdout_bytes', 0)} + {record.get('stderr_bytes', 0)} B",
                    str(record.get("plan_id", "")),
                )
                for column, value in enumerate(values):
                    self.activity_table.setItem(row, column, QTableWidgetItem(value))

        def _open_activity_row(self, row: int, _column: int) -> None:
            if row < 0 or row >= len(getattr(self, "activity_records", [])):
                return
            record = self.activity_records[row]
            try:
                output = bounded_read(
                    record["stdout_path"],
                    expected_sha256=record["stdout_sha256"],
                    expected_size=record["stdout_bytes"],
                )
                errors = bounded_read(
                    record["stderr_path"],
                    expected_sha256=record["stderr_sha256"],
                    expected_size=record["stderr_bytes"],
                )
            except Exception as error:
                self._error(str(error))
                return
            authenticated_text = output + ("\n--- stderr ---\n" + errors if errors else "")
            self.activity_output.setPlainText(authenticated_text[-12000:])
            dialog = QDialog(self)
            action = str(record.get("action", ""))
            action_label = (
                f"{action} (historical — action disabled)"
                if action in DISABLED_ACTIONS else action
            )
            dialog.setWindowTitle(f"Activity — {action_label}")
            dialog.resize(900, 620)
            layout = QVBoxLayout(dialog)
            viewer = QPlainTextEdit()
            viewer.setReadOnly(True)
            viewer.setPlainText(authenticated_text)
            layout.addWidget(viewer)
            buttons = QDialogButtonBox(QDialogButtonBox.Close)
            buttons.rejected.connect(dialog.reject)
            layout.addWidget(buttons)
            dialog.exec()

        def _error(self, message: str) -> None:
            QMessageBox.critical(self, APP_NAME, message[:8192])
            self.statusBar().showMessage("Operation blocked or failed", 5000)

        def _load_settings(self) -> None:
            try:
                data = json.loads(bounded_read(str(self.paths["settings"]), 1024 * 1024))
                profile = str(data.get("profile", "default"))
                profile_path(self.home, profile)
                index = self.profile_combo.findText(profile)
                if index < 0:
                    self.profile_combo.addItem(profile)
                    index = self.profile_combo.findText(profile)
                self.profile_combo.setCurrentIndex(index)
                page = str(data.get("page", "discover"))
                for row in range(self.sidebar.count()):
                    if self.sidebar.item(row).data(Qt.UserRole) == page:
                        self.sidebar.setCurrentRow(row)
                        break
            except (OSError, ValueError, json.JSONDecodeError, PolicyError):
                pass

        def _save_settings(self) -> None:
            try:
                profile = self.current_profile()
            except PolicyError:
                profile = "default"
            value = {"profile": profile, "page": self.current_page()}
            atomic_settings(self.paths["settings"], value)

    application = QApplication(sys.argv)
    application.setApplicationName(APP_NAME)
    application.setApplicationVersion(VERSION)
    application.setOrganizationName("Security Ops")
    application.setStyleSheet(
        """
        QMainWindow, QWidget { background: #080d12; color: #e7f6f8; }
        QToolBar { background: #0b141c; border: 0; border-bottom: 1px solid #17313b; padding: 8px; }
        #brand { color: #37e6ff; font-weight: 800; letter-spacing: 1.5px; }
        #sidebar { background: #0b141c; border: 0; padding: 14px 8px; outline: 0; }
        #sidebar::item { padding: 13px 16px; margin: 3px 4px; border-radius: 8px; }
        #sidebar::item:selected { background: #12313b; color: #65efff; }
        #pageHeading { font-size: 25px; font-weight: 700; color: #f3fcfd; }
        #dialogHeading, #detailHeading { font-size: 18px; font-weight: 700; color: #65efff; }
        #pageSubtitle, #muted { color: #9bb1b8; }
        #warningText { color: #ffd479; }
        #card { background: #0e1922; border: 1px solid #193541; border-radius: 10px; padding: 16px; }
        QPushButton { background: #12313b; border: 1px solid #216174; border-radius: 7px; padding: 8px 14px; }
        QPushButton:hover { background: #174554; }
        QPushButton:disabled { color: #66777d; background: #10181d; border-color: #26333a; }
        QLineEdit, QComboBox, QPlainTextEdit, QTextBrowser, QTableWidget {
            background: #0c151d; border: 1px solid #1d3d48; border-radius: 7px; padding: 7px;
            selection-background-color: #1c6678; selection-color: #ffffff;
        }
        QHeaderView::section { background: #11242d; color: #b9edf3; border: 0; padding: 8px; }
        QTableWidget { gridline-color: #17313b; alternate-background-color: #0f1a22; }
        QStatusBar { background: #0b141c; border-top: 1px solid #17313b; }
        QProgressBar { border: 0; background: #101d25; height: 5px; }
        QProgressBar::chunk { background: #37e6ff; }
        QScrollBar:vertical { background: #0b141c; width: 12px; }
        QScrollBar::handle:vertical { background: #24505e; min-height: 24px; border-radius: 5px; }
        """
    )
    default_font = QFont(application.font())
    default_font.setPointSize(max(default_font.pointSize(), 10))
    application.setFont(default_font)
    window = MainWindow()
    if smoke_evidence is not None:
        window.resize(smoke_width, smoke_height)
        window._apply_responsive_layout(smoke_width)
    window.show()
    if smoke_evidence is not None:
        smoke_evidence = smoke_evidence.resolve()
        def publish_smoke() -> None:
            try:
                atomic_settings(smoke_evidence, window.accessibility_snapshot(scale_factor=smoke_scale))
            except Exception as error:
                print(f"securityops-guix-center: offscreen smoke failed: {error}", file=sys.stderr)
                application.exit(3)
                return
            application.quit()
        QTimer.singleShot(0, publish_smoke)
    return application.exec()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securityops-guix-center")
    parser.add_argument("--headless-contract", action="store_true")
    parser.add_argument("--phase37-contract", action="store_true")
    parser.add_argument("--phase37-capabilities", action="store_true")
    parser.add_argument("--phase37-selftest", action="store_true")
    parser.add_argument("--ui-model", action="store_true")
    parser.add_argument("--headless-ui-snapshot", action="store_true")
    parser.add_argument("--width", type=int, default=1320)
    parser.add_argument("--height", type=int, default=820)
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument("--qt-offscreen-smoke", type=Path)
    parser.add_argument("--version", action="store_true")
    parsed_argv = sys.argv[1:] if argv is None else argv
    args, qt_args = parser.parse_known_args(parsed_argv)
    # Qt must only receive its own arguments. Security Ops control flags are
    # consumed here and never leaked into QApplication's parser.
    sys.argv = [sys.argv[0], *qt_args]
    if args.version:
        print(f"{APP_NAME} {VERSION}")
        return 0
    if args.headless_contract:
        print(json.dumps(headless_contract(), sort_keys=True, indent=2))
        return 0
    if args.phase37_contract:
        print(json.dumps(phase37_contract(), sort_keys=True, indent=2))
        return 0
    if args.phase37_capabilities:
        print(json.dumps(capability_report(), sort_keys=True, indent=2))
        return 0
    if args.phase37_selftest:
        print(json.dumps(phase37_selftest(), sort_keys=True, indent=2))
        return 0
    if args.ui_model:
        print(json.dumps(ui_model(), sort_keys=True, indent=2))
        return 0
    if args.headless_ui_snapshot:
        print(json.dumps(render_headless_snapshot(
            width_px=args.width, height_px=args.height, scale_factor=args.scale
        ), sort_keys=True, indent=2))
        return 0
    if args.qt_offscreen_smoke is not None:
        os.environ["QT_SCALE_FACTOR"] = str(args.scale)
    return run_gui(
        smoke_evidence=args.qt_offscreen_smoke,
        smoke_width=args.width, smoke_height=args.height, smoke_scale=args.scale,
    )


if __name__ == "__main__":
    raise SystemExit(main())
