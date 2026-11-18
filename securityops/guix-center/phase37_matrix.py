#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=646dcaec83f75b6a82e7bedaf9aab9d6 owner="Cristian Cezar Mois\u00e9s"
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-SecurityOps-Commercial
"""Bounded Phase 37 execution matrix for Security Ops Guix Center.

Portable cache, journal, and state-model measurements execute on any supported
Linux host. Guix, Qt, KVM, AF_VSOCK, kernel, installer, desktop, and ISO gates
remain explicit capability observations and are never inferred from portable
results.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from guix_backend import (  # noqa: E402
    ACTIONS, DISABLED_ACTIONS, EXECUTABLE_ACTIONS, GC_DELETE_BLOCKER,
    MUTATING_ACTIONS, CatalogCache, PolicyError,
    admit_guix_executable, canonical_json_bytes, create_transaction_plan,
    parse_installed_packages, parse_transaction_receipt,
)
from phase37_guix_center import (  # noqa: E402
    BLOCKERS, PAGES,
    OperationJournal,
    PageStateMachine,
    capability_report,
    classify_failure, execute_transaction_plan_journaled,
    parse_capability_report,
    phase37_contract_digest,
    validate_accessibility_snapshot,
)
import phase46_guix_execution as phase46_guix  # noqa: E402

FORMAT = "securityops-phase37-execution-matrix/1"
STATUS = "PASS_PHASE37_PORTABLE_MATRIX_WITH_CAPABILITY_GATES"
DOMAIN = b"SECURITYOPS-PHASE37-EXECUTION-MATRIX-V1\x00"


def _digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(DOMAIN + canonical_json_bytes(value)).hexdigest()


def _percentile(values: list[int], percentile: float) -> int:
    if not values:
        raise PolicyError("cannot calculate a percentile from an empty sample")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _rss_bytes() -> int | None:
    try:
        import psutil  # type: ignore
        return int(psutil.Process(os.getpid()).memory_info().rss)
    except Exception:
        return None


def _records(count: int) -> Iterable[dict[str, str]]:
    for index in range(count):
        yield {
            "name": f"package-{index:06d}",
            "version": f"1.{index % 100}.{index % 17}",
            "output": "out",
            "synopsis": f"Security Ops utility group {index % 257}",
            "description": f"Synthetic bounded catalog record {index}",
            "location": f"gnu/packages/phase37-{index % 97}.scm:{index + 1}",
        }


def benchmark_catalog(*, rows: int, search_iterations: int = 240) -> dict[str, Any]:
    if type(rows) is not int or not 1_000 <= rows <= 200_000:
        raise PolicyError("catalog benchmark rows are outside the bounded range")
    if type(search_iterations) is not int or not 20 <= search_iterations <= 10_000:
        raise PolicyError("catalog search iteration count is outside the bounded range")
    with tempfile.TemporaryDirectory(prefix="securityops-phase37-catalog-") as raw:
        database = Path(raw) / "catalog.sqlite3"
        before_rss = _rss_bytes()
        started = time.perf_counter_ns()
        cache = CatalogCache(database)
        initialized = time.perf_counter_ns()
        inserted = cache.replace_packages(_records(rows), updated_unix=1_700_000_000)
        populated = time.perf_counter_ns()
        queries = (
            "package-000001", "package-050000", "utility group 17", "%", "_",
            "not-present-phase37",
        )
        latencies: list[int] = []
        result_counts: list[int] = []
        for index in range(search_iterations):
            query = queries[index % len(queries)]
            tick = time.perf_counter_ns()
            result = cache.search(query, limit=100, offset=0)
            latencies.append(time.perf_counter_ns() - tick)
            result_counts.append(len(result))

        def concurrent_read(index: int) -> int:
            query = queries[index % len(queries)]
            return len(cache.search(query, limit=100, offset=0))

        concurrent_started = time.perf_counter_ns()
        with ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_counts = list(pool.map(concurrent_read, range(512)))
        concurrent_finished = time.perf_counter_ns()
        updated = cache.updated_unix()
        integrity_before = cache.verify_integrity()
        checkpoint = cache.checkpoint()
        integrity_after = cache.verify_integrity()
        cache.close()
        finished = time.perf_counter_ns()
        after_rss = _rss_bytes()
        return {
            "scope": "sqlite-catalog-and-python-backend-only",
            "not_end_to_end_qt_or_guix_evidence": True,
            "rows_requested": rows,
            "rows_inserted": inserted,
            "database_bytes": database.stat().st_size,
            "startup_cold_ns": initialized - started,
            "populate_ns": populated - initialized,
            "total_ns": finished - started,
            "insert_rows_per_second": round(rows / ((populated - initialized) / 1e9), 2),
            "search_samples": len(latencies),
            "search_median_ns": int(statistics.median(latencies)),
            "search_p95_ns": _percentile(latencies, 0.95),
            "search_p99_ns": _percentile(latencies, 0.99),
            "search_max_ns": max(latencies),
            "result_count_min": min(result_counts),
            "result_count_max": max(result_counts),
            "concurrent_reads": len(concurrent_counts),
            "concurrent_workers": 8,
            "concurrent_duration_ns": concurrent_finished - concurrent_started,
            "concurrent_result_count_min": min(concurrent_counts),
            "concurrent_result_count_max": max(concurrent_counts),
            "updated_unix": updated,
            "integrity_before": integrity_before,
            "wal_checkpoint": checkpoint,
            "integrity_after": integrity_after,
            "rss_before_bytes": before_rss,
            "rss_after_bytes": after_rss,
            "rss_delta_bytes": (
                after_rss - before_rss
                if before_rss is not None and after_rss is not None else None
            ),
        }


def profile_and_generation_pagination_matrix(
    *, installed_rows: int = 25_000, generation_rows: int = 50_000, page_size: int = 100,
) -> dict[str, Any]:
    """Measure bounded parsing and pagination without claiming real Guix evidence."""
    if not 1_000 <= installed_rows <= 100_000:
        raise PolicyError("installed-profile row count is outside the bounded range")
    if not 1_000 <= generation_rows <= 200_000:
        raise PolicyError("generation row count is outside the bounded range")
    if not 10 <= page_size <= 1_000:
        raise PolicyError("pagination size is outside the bounded range")
    installed_text = "".join(
        f"package-{index:06d}\t1.{index % 100}.{index % 17}\tout\t"
        f"/gnu/store/{hashlib.sha256(str(index).encode()).hexdigest()[:32]}-package-{index:06d}\n"
        for index in range(installed_rows)
    )
    parse_started = time.perf_counter_ns()
    installed = parse_installed_packages(installed_text)
    parse_finished = time.perf_counter_ns()
    generations = tuple(range(generation_rows, 0, -1))
    page_started = time.perf_counter_ns()
    installed_pages = [
        installed[offset:offset + page_size]
        for offset in range(0, len(installed), page_size)
    ]
    generation_pages = [
        generations[offset:offset + page_size]
        for offset in range(0, len(generations), page_size)
    ]
    page_finished = time.perf_counter_ns()
    return {
        "scope": "synthetic-parser-and-pagination-only",
        "not_real_guix_profile_or_qt_evidence": True,
        "installed_rows": len(installed),
        "installed_input_bytes": len(installed_text.encode("utf-8")),
        "installed_parse_ns": parse_finished - parse_started,
        "installed_pages": len(installed_pages),
        "generation_rows": len(generations),
        "generation_pages": len(generation_pages),
        "page_size": page_size,
        "pagination_ns": page_finished - page_started,
        "first_installed": installed_pages[0][0]["name"],
        "last_installed": installed_pages[-1][-1]["name"],
        "first_generation": generation_pages[0][0],
        "last_generation": generation_pages[-1][-1],
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def mutation_serialization_matrix() -> dict[str, Any]:
    """Prove concurrent same-profile mutations queue and never overlap."""
    with tempfile.TemporaryDirectory(prefix="securityops-phase37-serialization-") as raw:
        root = Path(raw)
        home = root / "home/alice"
        home.mkdir(parents=True)
        marker = root / "intervals.log"
        guix = root / "guix"
        guix.write_text(
            f"#!{Path(sys.executable).resolve(strict=True)}\n"
            "import os,time\n"
            f"p={str(marker)!r}\n"
            "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)\n"
            "os.write(fd,f'S {os.getpid()} {time.monotonic_ns()}\\n'.encode())\n"
            "os.fsync(fd); time.sleep(0.20)\n"
            "os.write(fd,f'E {os.getpid()} {time.monotonic_ns()}\\n'.encode())\n"
            "os.fsync(fd); os.close(fd)\n",
            encoding="utf-8",
        )
        guix.chmod(0o500)
        admitted = admit_guix_executable(guix, fixture_mode=True)
        state_root = root / "state"
        # Establish the shared journal root before concurrent workers enter. The
        # directory helper is also race-safe and is tested independently.
        OperationJournal(state_root / "journal")
        plans = [
            create_transaction_plan(
                admitted=admitted, home=home, profile="default", action="install",
                package_specs=(f"fixture-{index}",), timeout_seconds=10,
                operation_nonce=f"{index + 1:032x}",
                created_unix=1_900_000_000 + index,
            )
            for index in range(2)
        ]

        def execute(plan):
            return execute_transaction_plan_journaled(
                plan, home=home, state_root=state_root,
                confirmation_plan_id=plan.plan_id, now_unix=1_900_000_100,
            )

        started = time.perf_counter_ns()
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(execute, plans))
        finished = time.perf_counter_ns()

        events: dict[int, dict[str, int]] = {}
        for line in marker.read_text(encoding="utf-8").splitlines():
            kind, raw_pid, raw_time = line.split()
            events.setdefault(int(raw_pid), {})[kind] = int(raw_time)
        intervals = sorted((item["S"], item["E"]) for item in events.values())
        if len(intervals) != 2 or any(begin >= end for begin, end in intervals):
            raise PolicyError("fixture mutation serialization evidence is incomplete")
        serialized = intervals[0][1] <= intervals[1][0]
        if not serialized:
            raise PolicyError("same-profile fixture mutations overlapped")
        trusted = [
            parse_transaction_receipt(item, state_root=state_root)
            for item in receipts
        ]
        journals = [
            OperationJournal(state_root / "journal").load(plan.operation_nonce)
            for plan in plans
        ]
        if any(item["state"] != "succeeded" for item in journals):
            raise PolicyError("queued same-profile mutation did not close successfully")
        return {
            "scope": "fixture-locking-only",
            "not_real_guix_transaction_evidence": True,
            "mutations": 2,
            "mutations_attempted": 2,
            "mutations_completed": 2,
            "bounded_queueing": True,
            "same_profile": True,
            "serialized": True,
            "elapsed_ns": finished - started,
            "intervals": [[begin, end] for begin, end in intervals],
            "receipt_digests": [item["receipt_digest"] for item in trusted],
            "journal_digests": [item["record_digest"] for item in journals],
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }

def failure_classification_matrix() -> dict[str, Any]:
    base = {"timed_out": False, "output_limit_exceeded": False}
    vectors = {
        "timeout": ({**base, "timed_out": True}, ""),
        "output-limit": ({**base, "output_limit_exceeded": True}, ""),
        "guix-daemon-unavailable": (base, "failed to connect to guix-daemon"),
        "network-unavailable": (base, "network is unreachable"),
        "trust-or-signature": (base, "substitute has an invalid signature"),
        "disk-full": (base, "No space left on device"),
        "permission": (base, "Permission denied"),
        "command-failed": (base, "unclassified failure"),
    }
    observed = {
        expected: classify_failure(receipt, stderr)
        for expected, (receipt, stderr) in vectors.items()
    }
    if any(expected != actual for expected, actual in observed.items()):
        raise PolicyError("failure classification matrix diverged")
    return {
        "scope": "bounded-text-classification-only",
        "vectors": observed,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def journal_fault_matrix(*, operations: int = 200) -> dict[str, Any]:
    if type(operations) is not int or not 10 <= operations <= 2_000:
        raise PolicyError("journal operation count is outside the bounded range")
    with tempfile.TemporaryDirectory(prefix="securityops-phase37-journal-") as raw:
        root = Path(raw) / "journal"
        journal = OperationJournal(root)
        created: list[str] = []
        for index in range(operations):
            operation_id = f"{index + 1:032x}"
            dead_controller = index % 4 == 0
            entry = journal.create(
                plan_id=hashlib.sha256(f"plan-{index}".encode()).hexdigest(),
                action="search" if index % 2 == 0 else "install",
                profile="default" if index % 3 else "development",
                operation_id=operation_id,
                now_unix=index * 3,
                controller_pid=(2_000_000_000 if dead_controller else None),
                controller_start_ticks=(1 if dead_controller else None),
            )
            created.append(entry["operation_id"])
            if index % 4 == 0:
                # A deliberately non-existent controller models power loss.
                journal.transition(operation_id, "running", now_unix=index * 3 + 1)
            elif index % 4 == 1:
                journal.transition(operation_id, "cancelled", reason="fault-injection", now_unix=index * 3 + 1)
            elif index % 4 == 2:
                journal.transition(operation_id, "running", now_unix=index * 3 + 1)
                journal.transition(
                    operation_id, "succeeded",
                    receipt_digest=hashlib.sha256(f"receipt-{index}".encode()).hexdigest(),
                    now_unix=index * 3 + 2,
                )
            else:
                journal.transition(operation_id, "running", now_unix=index * 3 + 1)
                journal.transition(operation_id, "failed", reason="synthetic-failure", now_unix=index * 3 + 2)
        recovered = journal.recover_interrupted(now_unix=operations * 3 + 1)
        records = journal.list_records()
        states: dict[str, int] = {}
        history_records = 0
        for operation_id in created:
            history = journal.load_history(operation_id)
            history_records += len(history)
        for record in records:
            states[record["state"]] = states.get(record["state"], 0) + 1
        stray = root / ".power-loss-before-rename.tmp"
        stray.write_bytes(b"partial")
        stray.chmod(0o600)
        # Non-JSON temporary files cannot become activity records.
        after_stray = journal.list_records()
        return {
            "operations": operations,
            "history_records": history_records,
            "recovered_interrupted": len(recovered),
            "terminal_records": len(records),
            "states": dict(sorted(states.items())),
            "temporary_file_ignored": len(after_stray) == len(records),
            "append_only": all(len(journal.load_history(item)) >= 2 for item in created),
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }



def fixture_action_matrix() -> dict[str, Any]:
    """Execute safe actions and prove disabled actions reject without dispatch.

    This validates the plan/executor/journal/receipt pipeline only. The fixture
    is never represented as a real Guix daemon, package transaction, or
    production gate.
    """
    with tempfile.TemporaryDirectory(prefix="securityops-phase37-actions-") as raw:
        root = Path(raw)
        home = root / "home" / "alice"
        home.mkdir(parents=True)
        guix = root / "guix"
        guix.write_text(
            f"#!{Path(sys.executable).resolve(strict=True)}\n"
            "import sys\n"
            "if len(sys.argv) > 1 and sys.argv[1] == 'search':\n"
            " print('name: hello\\nversion: 2.12.1\\noutput: out\\n'"
            "       'synopsis: Hello\\ndescription: Fixture\\n'"
            "       'location: gnu/packages/base.scm:1\\n')\n"
            "elif '--list-installed' in sys.argv:\n"
            " print('hello\\t2.12.1\\tout\\t/gnu/store/fixture-hello')\n"
            "else:\n"
            " print('fixture-guix', *sys.argv[1:])\n",
            encoding="utf-8",
        )
        guix.chmod(0o500)
        channels = root / "channels.scm"
        channels.write_text("(list 'securityops)\n", encoding="utf-8")
        channels.chmod(0o600)
        admitted = admit_guix_executable(guix, fixture_mode=True)
        state_root = root / "state"
        results: list[dict[str, Any]] = []
        for index, action in enumerate(EXECUTABLE_ACTIONS, start=1):
            kwargs: dict[str, Any] = {
                "admitted": admitted,
                "home": home,
                "profile": "default",
                "action": action,
                "timeout_seconds": 15,
                "operation_nonce": f"{index:032x}",
                "created_unix": 1_800_000_000 + index,
            }
            if action == "search":
                kwargs["query"] = "hello"
            elif action == "show":
                kwargs["package_specs"] = ("hello",)
            elif action in {"install", "remove", "upgrade"}:
                kwargs["package_specs"] = ("hello",)
            elif action == "switch-generation":
                kwargs["generation"] = 1
            elif action == "delete-generations":
                kwargs["delete_generations"] = "30d"
            elif action == "pull":
                kwargs["channels_file"] = channels
                kwargs["owner_uid"] = os.getuid()
            plan = create_transaction_plan(**kwargs)
            receipt = execute_transaction_plan_journaled(
                plan,
                home=home,
                state_root=state_root,
                confirmation_plan_id=(plan.plan_id if action in MUTATING_ACTIONS else None),
                now_unix=1_800_000_001 + index,
            )
            trusted = parse_transaction_receipt(receipt, state_root=state_root)
            journal = OperationJournal(state_root / "journal").load(plan.operation_nonce)
            if not trusted["success"] or journal["state"] != "succeeded":
                raise PolicyError(f"fixture action did not close successfully: {action}")
            if journal["receipt_digest"] != trusted["receipt_digest"]:
                raise PolicyError("journal did not bind the authenticated receipt")
            results.append({
                "action": action,
                "argv": list(plan.argv[1:]),
                "plan_id": plan.plan_id,
                "receipt_digest": trusted["receipt_digest"],
                "journal_digest": journal["record_digest"],
            })
        rejected: list[dict[str, str]] = []
        for index, action in enumerate(
            DISABLED_ACTIONS, start=len(EXECUTABLE_ACTIONS) + 1
        ):
            try:
                create_transaction_plan(
                    admitted=admitted,
                    home=home,
                    profile="default",
                    action=action,
                    timeout_seconds=15,
                    operation_nonce=f"{index:032x}",
                    created_unix=1_800_000_000 + index,
                )
            except PolicyError as error:
                if str(error) != GC_DELETE_BLOCKER:
                    raise
                rejected.append({"action": action, "blocker": str(error)})
            else:
                raise PolicyError(f"disabled fixture action was accepted: {action}")
        return {
            "scope": "fixture-plan-executor-journal-receipt-only",
            "not_real_guix_transaction_evidence": True,
            "actions": results,
            "actions_executed": len(results),
            "actions_inventoried": list(ACTIONS),
            "actions_disabled": rejected,
            "disabled_actions_rejected": [item["action"] for item in rejected]
            == list(DISABLED_ACTIONS),
            "complete_action_inventory": (
                len(results) + len(rejected) == len(ACTIONS)
                and all(
                    action in {
                        item["action"] for item in (*results, *rejected)
                    }
                    for action in ACTIONS
                )
            ),
            "production_gates_approved": 0,
            "production_dispatch_allowed": False,
            "iso_release_allowed": False,
        }

def state_model_matrix(*, iterations: int = 10_000) -> dict[str, Any]:
    if type(iterations) is not int or not 8 <= iterations <= 1_000_000:
        raise PolicyError("state-model iteration count is outside the bounded range")
    model = PageStateMachine(now_unix=0)
    states = ("loading", "ready", "empty", "stale", "offline", "error")
    started = time.perf_counter_ns()
    for index in range(iterations):
        page = PAGES[index % len(PAGES)]
        model.transition(page, states[index % len(states)], f"state {index}", now_unix=index + 1)
    finished = time.perf_counter_ns()
    snapshot = model.snapshot()
    return {
        "iterations": iterations,
        "duration_ns": finished - started,
        "transitions_per_second": round(iterations / ((finished - started) / 1e9), 2),
        "page_count": len(snapshot["pages"]),
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def startup_matrix(frontend: Path, *, cold_runs: int = 5, warm_runs: int = 1_000) -> dict[str, Any]:
    if not frontend.is_absolute() or not frontend.is_file():
        raise PolicyError("frontend path is invalid")
    cold: list[int] = []
    for _ in range(cold_runs):
        started = time.perf_counter_ns()
        result = subprocess.run(
            [sys.executable, str(frontend), "--headless-contract"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=15, env={**os.environ, "PYTHONNOUSERSITE": "1"},
        )
        cold.append(time.perf_counter_ns() - started)
        if result.returncode != 0:
            raise PolicyError("headless cold-start process failed")
        json.loads(result.stdout)
    from securityops_guix_center import headless_contract
    started = time.perf_counter_ns()
    for _ in range(warm_runs):
        headless_contract()
    warm_total = time.perf_counter_ns() - started
    return {
        "scope": "headless-python-contract-only",
        "not_qt_startup_evidence": True,
        "cold_runs": cold_runs,
        "cold_median_ns": int(statistics.median(cold)),
        "cold_p95_ns": _percentile(cold, 0.95),
        "cold_max_ns": max(cold),
        "warm_runs": warm_runs,
        "warm_total_ns": warm_total,
        "warm_mean_ns": warm_total // warm_runs,
    }


def bounded_soak(cache_rows: int, seconds: float) -> dict[str, Any]:
    if not 0.1 <= seconds <= 28_800:
        raise PolicyError("soak duration is outside the bounded range")
    with tempfile.TemporaryDirectory(prefix="securityops-phase37-soak-") as raw:
        cache = CatalogCache(Path(raw) / "catalog.sqlite3")
        cache.replace_packages(_records(cache_rows), updated_unix=1)
        started = time.monotonic()
        iterations = 0
        failures = 0
        while time.monotonic() - started < seconds:
            try:
                cache.search(f"package-{iterations % cache_rows:06d}", limit=20)
                if iterations % 50 == 0:
                    cache.updated_unix()
            except Exception:
                failures += 1
            iterations += 1
        elapsed = time.monotonic() - started
        cache.close()
    return {
        "scope": "portable-cache-idle-refresh-soak",
        "required_production_seconds": 28_800,
        "executed_seconds": round(elapsed, 6),
        "full_required_soak_completed": elapsed >= 28_800,
        "iterations": iterations,
        "failures": failures,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
    }


def qt_offscreen_matrix(frontend: Path, output_root: Path) -> dict[str, Any]:
    report = capability_report(include_versions=False)
    if not report["gates_observed"]["qt_runtime"]:
        return {
            "status": "BLOCKED_PYSIDE6_UNAVAILABLE",
            "executed": False,
            "evidence": [],
            "matrix_vectors": 0,
        }
    vectors: list[dict[str, Any]] = []
    widths = (640, 1080, 1920)
    scales = (1.0, 1.25, 1.5, 2.0)
    for width in widths:
        for scale in scales:
            suffix = str(scale).replace(".", "_")
            evidence = output_root / f"qt-offscreen-{width}-scale-{suffix}.json"
            result = subprocess.run(
                [
                    sys.executable, str(frontend),
                    "--qt-offscreen-smoke", str(evidence),
                    "--width", str(width), "--height", "820",
                    "--scale", str(scale),
                ],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, timeout=60,
                env={
                    **os.environ, "QT_QPA_PLATFORM": "offscreen",
                    "QT_SCALE_FACTOR": str(scale), "PYTHONNOUSERSITE": "1",
                },
            )
            if result.returncode != 0:
                return {
                    "status": "FAILED_QT_OFFSCREEN_EXECUTION",
                    "executed": True,
                    "returncode": result.returncode,
                    "width_px": width, "scale_factor": scale,
                    "stderr": result.stderr.decode("utf-8", errors="replace")[-4096:],
                    "evidence": [item["evidence"] for item in vectors],
                    "matrix_vectors": len(vectors),
                }
            snapshot = json.loads(evidence.read_text(encoding="utf-8"))
            validate_accessibility_snapshot(snapshot)
            viewport = snapshot["viewport"]
            if viewport["width_px"] != width or viewport["scale_factor"] != scale:
                raise PolicyError("Qt offscreen evidence does not bind its requested viewport")
            vectors.append({
                "width_px": width, "scale_factor": scale,
                "layout": viewport["layout"],
                "widget_count": len(snapshot["widgets"]),
                "evidence": str(evidence),
            })
    return {
        "status": "PASS_PHASE37_QT_OFFSCREEN_ACCESSIBILITY_HIDPI_LAYOUT_MATRIX",
        "executed": True,
        "returncode": 0,
        "evidence": [item["evidence"] for item in vectors],
        "matrix_vectors": len(vectors),
        "vectors": vectors,
    }


def guix_derivation_matrix(
    os_root: Path,
    output_root: Path,
    *,
    execution_profile: phase46_guix.VerifiedGuixExecutionProfile | None = None,
) -> dict[str, Any]:
    """Report why an explicitly admitted Guix build profile is required.

    Capability discovery must never execute an ambient Guix client.  A Store
    path alone does not authenticate the channel graph, client, daemon socket,
    daemon executable, ACL, policy arguments, or private Store database.
    Phase 46 performs admitted builds through a separate bounded executor.
    """
    if execution_profile is not None:
        return phase46_guix.execute_derivation_matrix(
            execution_profile,
            os_root=os_root,
            output_root=output_root,
        )
    report = capability_report(include_versions=False)
    return {
        "status": phase46_guix.BLOCKER,
        "executed": False,
        "store_resident_candidate_discovered": bool(
            report["gates_observed"]["guix_environment"]
        ),
        "store_residency_is_authentication": False,
        "ambient_guix_execution_allowed": False,
        "required_bindings": [
            "client-path-and-sha256",
            "daemon-socket-peer-pid-start-time-path-and-sha256",
            "closed-daemon-argv",
            "authenticated-channel-commit-and-introduction",
            "substitute-url-and-exact-public-key-acl",
            "private-store-state-and-database",
            "independent-clean-build-contexts",
            "fixed-publisher-authenticated-executor",
        ],
    }


def run_matrix(
    *, os_root: Path, output_root: Path, rows: int, soak_seconds: float,
    progress: bool = False,
    guix_execution_profile: phase46_guix.VerifiedGuixExecutionProfile | None = None,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(output_root, 0o700)
    frontend = os_root / "securityops/guix-center/securityops_guix_center.py"
    capabilities = capability_report()
    parse_capability_report(capabilities)
    def announce(label: str) -> None:
        if progress:
            print(f"phase37-matrix: {label}", file=sys.stderr, flush=True)

    catalogs = []
    for catalog_rows in (50_000, 100_000):
        announce(f"catalog-{catalog_rows}")
        catalogs.append(benchmark_catalog(rows=catalog_rows))
    announce("profile-and-generation-pagination")
    pagination = profile_and_generation_pagination_matrix()
    announce("fixture-action-matrix")
    fixture_actions = fixture_action_matrix()
    announce("mutation-serialization")
    mutation = mutation_serialization_matrix()
    announce("failure-classification")
    failures = failure_classification_matrix()
    announce("journal-faults")
    journal = journal_fault_matrix()
    announce("state-model")
    state_model = state_model_matrix()
    announce("startup")
    startup = startup_matrix(frontend)
    announce("bounded-soak")
    soak = bounded_soak(min(rows, 10_000), soak_seconds)
    announce("qt-offscreen")
    qt_matrix = qt_offscreen_matrix(frontend, output_root)
    announce("guix-derivation")
    guix_matrix = guix_derivation_matrix(
        os_root,
        output_root,
        execution_profile=guix_execution_profile,
    )
    result: dict[str, Any] = {
        "format": FORMAT,
        "status": STATUS,
        "phase37_contract_digest": phase37_contract_digest(),
        "capabilities": capabilities,
        "portable": {
            "catalogs": catalogs,
            "profile_and_generation_pagination": pagination,
            "fixture_actions": fixture_actions,
            "mutation_serialization": mutation,
            "failure_classification": failures,
            "journal_faults": journal,
            "state_model": state_model,
            "startup": startup,
            "soak": soak,
        },
        "capability_gated": {
            "qt_offscreen": qt_matrix,
            "guix_derivation": guix_matrix,
            "graphical_session": {"status": "BLOCKED_REAL_GRAPHICAL_SESSION_REQUIRED", "executed": False},
            "real_guix_transactions": {"status": "BLOCKED_DISPOSABLE_REAL_GUIX_MATRIX_REQUIRED", "executed": False},
            "foreign_distributions": {"status": "BLOCKED_TWO_FOREIGN_DISTRIBUTIONS_REQUIRED", "executed": False},
            "linux_7_2": {"status": "BLOCKED_GUIX_BUILD_AND_BOOT_REQUIRED", "executed": False},
            "personal_vm": {"status": "BLOCKED_KVM_NETWORK_PERSISTENCE_REQUIRED", "executed": False},
            "gaming_vm": {"status": "BLOCKED_KVM_GPU_AUDIO_APPLICATIONS_REQUIRED", "executed": False},
            "installer2": {"status": "BLOCKED_UEFI_BIOS_DISK_MATRIX_REQUIRED", "executed": False},
            "desktops": {"status": "BLOCKED_BOOTED_SESSION_AND_CLOSURE_MATRIX_REQUIRED", "executed": False},
            "microvm_af_vsock": {"status": "BLOCKED_REAL_KVM_AF_VSOCK_REQUIRED", "executed": False},
            "iso": {"status": "BLOCKED_TWO_BOOTABLE_ISO_BUILDS_REQUIRED", "executed": False},
        },
        "blockers": list(BLOCKERS),
        "production_gates_approved": 0,
        "production_dispatch_allowed": False,
        "iso_release_allowed": False,
        "iso_bytes_present": False,
    }
    result["evidence_digest"] = _digest(result)
    return result


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise PolicyError("evidence path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        payload = canonical_json_bytes(value) + b"\n"
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = ""
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securityops-phase37-matrix")
    parser.add_argument("--os-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--soak-seconds", type=float, default=30.0)
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args(argv)
    os_root = args.os_root.resolve()
    output = args.output.resolve()
    matrix = run_matrix(
        os_root=os_root, output_root=output.parent / "phase37-matrix-artifacts",
        rows=args.rows, soak_seconds=args.soak_seconds, progress=args.progress,
    )
    atomic_json(output, matrix)
    print(json.dumps(matrix, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
