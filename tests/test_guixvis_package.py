# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=8d5f2cf1a8145eebaf88d2313ba882af owner="Cristian Cezar Mois\u00e9s"
"""Exercise actual reference-free Cargo phases, without invoking a compiler."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECK = r'''
(use-modules (guix packages) (guix gexp) (ice-9 match) (srfi srfi-1)
             (securityops packages guixvis))
(match (cdr (command-line))
  ((phase jobs parallel tests)
   (let* ((name (string->symbol phase))
          (arguments (package-arguments guixvis))
          (forms (gexp->approximate-sexp (cadr (memq #:phases arguments))))
          (replacements
           (filter (match-lambda
                     (('replace ('quote actual) body) (eq? actual name))
                     (_ #f))
                   (cddr forms)))
          (mock (make-module))
          (calls '()))
     (unless (and (memq name '(build check)) (= 1 (length replacements)))
       (error "missing or duplicate reviewed Cargo phase"))
     ;; Only these two reference-free lambdas are evaluated, not configure or
     ;; install. This mock module is a functional fixture, not a sandbox.
     (module-use! mock (resolve-interface '(guile)))
     (module-define! mock 'parallel-job-count (make-parameter (string->number jobs)))
     (module-define! mock 'invoke
       (lambda args (set! calls (cons args calls)) #t))
     (let* ((body (caddar replacements))
            (function (eval body mock))
            (enabled? (string=? tests "yes"))
            (expected-jobs (if (string=? parallel "no") "1" jobs))
            (expected
             (if (and (eq? name 'check) (not enabled?)) '()
                 (list (append
                        (if (eq? name 'build)
                            '("cargo" "build" "--frozen" "--offline" "--release")
                            '("cargo" "test" "--frozen" "--offline"))
                        (list "--features" "web" "--jobs" expected-jobs))))))
       (if (string=? parallel "default")
           (function #:tests? enabled? #:unrelated-phase-argument #t)
           (function #:tests? enabled? #:unrelated-phase-argument #t
                     #:parallel-build? (string=? parallel "yes")))
       (unless (equal? calls expected)
         (error "Cargo phase arguments differ" calls expected))
       (display "CARGO_PHASE_OK\n"))))
  (_ (error "invalid test arguments")))
'''


class GuixvisPackageTests(unittest.TestCase):
    def check_phase(self, phase, jobs, parallel="default", tests="yes"):
        guix = shutil.which("guix")
        self.assertIsNotNone(guix, "Guix is required; missing tools are not PASS")
        environment = os.environ.copy()
        environment["GUIX_DAEMON_SOCKET"] = "/nonexistent/securityops-test-no-daemon"
        with tempfile.TemporaryDirectory(prefix="securityops-cargo-phase-") as temporary:
            script = Path(temporary) / "check.scm"
            script.write_text(CHECK, encoding="utf-8")
            result = subprocess.run(
                [guix, "repl", "-q", "-L", str(ROOT), "--", str(script),
                 phase, str(jobs), parallel, tests],
                env=environment, cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "CARGO_PHASE_OK\n")

    def test_build_defaults_to_guix_job_count(self):
        for jobs in (1, 3):
            with self.subTest(jobs=jobs):
                self.check_phase("build", jobs)

    def test_check_defaults_to_guix_job_count(self):
        for jobs in (1, 3):
            with self.subTest(jobs=jobs):
                self.check_phase("check", jobs)

    def test_explicit_parallel_build_respects_guix_job_count(self):
        for phase in ("build", "check"):
            with self.subTest(phase=phase):
                self.check_phase(phase, 3, "yes")

    def test_disabled_parallelism_uses_one_job(self):
        for phase in ("build", "check"):
            with self.subTest(phase=phase):
                self.check_phase(phase, 3, "no")

    def test_disabled_tests_do_not_invoke_cargo(self):
        for parallel in ("default", "yes", "no"):
            with self.subTest(parallel=parallel):
                self.check_phase("check", 3, parallel, "no")
