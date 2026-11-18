# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=f26ab8e92a325a46b9734209aa257255 owner="Cristian Cezar Mois\u00e9s"
"""Real lock/CLI/wrapper tests on synthetic repositories; no Guix builds."""
import fcntl
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader('ctl_lock_tests', str(ROOT / 'securityopsctl'))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
CTL = importlib.util.module_from_spec(SPEC)
sys.modules[LOADER.name] = CTL
LOADER.exec_module(CTL)


class BuildLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='securityops-lock-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = CTL.Repository(self.root)
        shutil.copy2(ROOT / 'securityopsctl', self.root / 'securityopsctl')

    def cli(self, *args, pass_fds=()):
        return subprocess.run([sys.executable, '-I', '-B', str(self.root / 'securityopsctl'), *args],
                              env={'PATH':'/nonexistent'}, pass_fds=pass_fds,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=5)

    def prepare(self):
        result = self.cli('prepare-validation')
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.repo.lock_path

    def test_prepare_without_settings_or_external_commands(self):
        self.prepare()
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['out','securityopsctl'])
        metadata = self.repo.lock_path.stat()
        self.assertEqual((stat.S_IMODE(metadata.st_mode), metadata.st_nlink, metadata.st_uid),
                         (0o600, 1, os.getuid()))
        self.assertEqual(metadata.st_size, 0)

    def test_existing_private_lock_is_not_rewritten(self):
        path = self.prepare()
        path.write_bytes(b'fixture-lock-content')
        before = path.stat()
        self.prepare()
        after = path.stat()
        self.assertEqual((before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns),
                         (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
        self.assertEqual(path.read_bytes(), b'fixture-lock-content')

    def test_unsafe_existing_modes_refused_without_repair(self):
        path = self.prepare()
        for mode in (0o644, 0o660, 0o400):
            with self.subTest(mode=oct(mode)):
                path.chmod(mode)
                before = path.stat()
                result = self.cli('prepare-validation')
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(path.stat(), before)

    def test_hardlink_refused_by_existing_buildlock(self):
        self.repo.out_dir.mkdir()
        path = self.repo.lock_path
        path.touch(mode=0o600)
        os.link(path, self.root / 'alias')
        before = path.stat()
        with self.assertRaises(CTL.MaintainerError):
            with CTL.BuildLock(self.repo):
                self.fail('hardlink admitted')
        self.assertEqual(path.stat(), before)

    def test_symlink_out_and_leaf_refused_without_touching_target(self):
        outside = self.root / 'outside'
        outside.mkdir()
        self.repo.out_dir.symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.assertEqual(list(outside.iterdir()), [])
        self.repo.out_dir.unlink()
        self.repo.out_dir.mkdir()
        self.repo.lock_path.symlink_to(outside / 'not-created')
        self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.assertEqual(list(outside.iterdir()), [])

    def test_fifo_refused_without_blocking(self):
        self.repo.out_dir.mkdir()
        os.mkfifo(self.repo.lock_path, 0o600)
        self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.assertTrue(stat.S_ISFIFO(self.repo.lock_path.lstat().st_mode))

    def test_unsafe_directory_refused(self):
        self.repo.out_dir.mkdir(mode=0o777)
        self.repo.out_dir.chmod(0o777)
        self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.assertFalse(self.repo.lock_path.exists())

    def test_shared_and_exclusive_contention_preserve_inode(self):
        path = self.prepare()
        inode = path.stat().st_ino
        for kind in (fcntl.LOCK_SH, fcntl.LOCK_EX):
            with self.subTest(kind=kind), path.open('rb') as held:
                fcntl.flock(held, kind | fcntl.LOCK_NB)
                self.assertEqual(self.cli('prepare-validation').returncode, 1)
                self.assertEqual(path.stat().st_ino, inode)
        self.prepare()

    def test_inherited_check_does_not_unlock_parent(self):
        path = self.prepare()
        with path.open('r+b') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.cli('_build-lock', 'check', str(held.fileno()), pass_fds=(held.fileno(),))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.prepare()

    def test_rebinding_during_acquire_is_rejected_and_fds_closed(self):
        flock = fcntl.flock
        original_fds = len(list(Path('/proc/self/fd').iterdir()))

        def replace_after_flock(fd, flags):
            flock(fd, flags)
            self.repo.lock_path.rename(self.repo.out_dir / 'old')
            self.repo.lock_path.touch(mode=0o600)

        with mock.patch.object(CTL.fcntl, 'flock', side_effect=replace_after_flock):
            with self.assertRaises(CTL.MaintainerError):
                with CTL.BuildLock(self.repo):
                    self.fail('replacement admitted')
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), original_fds)

    def test_rebinding_at_context_exit_is_rejected(self):
        with self.assertRaises(CTL.MaintainerError):
            with CTL.BuildLock(self.repo):
                self.repo.lock_path.rename(self.repo.out_dir / 'old')
                self.repo.lock_path.touch(mode=0o600)

    def test_replaced_output_directory_is_rejected(self):
        with self.assertRaises(CTL.MaintainerError):
            with CTL.BuildLock(self.repo):
                self.repo.out_dir.rename(self.root / 'old-out')
                self.repo.out_dir.mkdir()
                self.repo.lock_path.touch(mode=0o600)

    def test_wrong_owner_simulation_is_rejected_before_create(self):
        # No privileged chown: simulate the UID boundary, label this test as
        # a simulation rather than a real cross-user filesystem execution.
        with mock.patch.object(CTL.os, 'getuid', return_value=os.getuid()+1):
            with self.assertRaises(CTL.MaintainerError):
                with CTL.BuildLock(self.repo):
                    self.fail('foreign-owned root admitted')
        self.assertFalse(self.repo.out_dir.exists())

    def copy_wrappers(self):
        for name in ('build.sh','make-iso.sh','securityops/installer/gen-config.sh',
                     'securityops/installer/security-ops-install'):
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)

    def wrapper(self, entry, mask='022', arguments=(), environment=None, pass_fds=(),
                guix_body='return 78;'):
        # Guix is an explicit failing test double, never a real transaction.
        env = {'PATH':os.environ['PATH']}
        env.update(environment or {})
        return subprocess.run(['bash', '-c',
                               'umask "$1"; shift; guix() { ' + guix_body + ' }; export -f guix; exec bash "$@"',
                               'lock-test', mask, str(self.root / entry), *arguments],
                              cwd=self.root, env=env, pass_fds=pass_fds,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)

    def test_wrappers_create_private_lock_under_both_umasks(self):
        self.copy_wrappers()
        for entry in ('build.sh', 'make-iso.sh'):
            for mask in ('022','077'):
                with self.subTest(entry=entry, mask=mask):
                    result = self.wrapper(entry, mask)
                    # build.sh stops at Guix double; make-iso.sh stops at absent
                    # settings during its real CLI validation, after locking.
                    self.assertEqual(result.returncode, 78 if entry == 'build.sh' else 1,
                                     result.stdout + result.stderr)
                    if entry == 'make-iso.sh':
                        self.assertIn('settings.json', result.stderr)
                    self.assertEqual(stat.S_IMODE(self.repo.lock_path.stat().st_mode), 0o600)
                    self.assertFalse(list(self.repo.out_dir.glob('*.iso')))
                    self.repo.lock_path.unlink()  # Only this test's disposable fixture.

    def test_wrapper_help_is_read_only(self):
        self.copy_wrappers()
        for entry in ('build.sh','make-iso.sh'):
            self.assertEqual(self.wrapper(entry, arguments=('--help',)).returncode, 0)
        self.assertFalse(self.repo.out_dir.exists())

    def test_forged_marker_does_not_create_or_bypass_lock(self):
        self.copy_wrappers()
        for entry in ('build.sh','make-iso.sh'):
            with self.subTest(entry=entry):
                result = self.wrapper(entry, environment={'SECURITYOPS_ISO_LOCK_HELD':'1'})
                self.assertEqual(result.returncode, 1)
                self.assertFalse(self.repo.lock_path.exists())

    def test_wrappers_refuse_unsafe_existing_and_contended_lock(self):
        self.copy_wrappers()
        path = self.prepare()
        for entry in ('build.sh','make-iso.sh'):
            with self.subTest(entry=entry):
                path.chmod(0o644)
                before = path.stat()
                self.assertEqual(self.wrapper(entry).returncode, 1)
                self.assertEqual(path.stat(), before)
                path.chmod(0o600)
                with path.open('rb') as held:
                    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    self.assertEqual(self.wrapper(entry).returncode, 1)

    def test_wrappers_reject_fifo_symlink_and_hardlink_without_build(self):
        self.copy_wrappers()
        self.repo.out_dir.mkdir()
        target = self.root / 'untouched'
        target.write_bytes(b'unchanged')
        target.chmod(0o600)
        for kind in ('fifo','symlink','hardlink'):
            with self.subTest(kind=kind):
                if kind == 'fifo':
                    os.mkfifo(self.repo.lock_path, 0o600)
                elif kind == 'symlink':
                    self.repo.lock_path.symlink_to(target)
                else:
                    os.link(target, self.repo.lock_path)
                for entry in ('build.sh','make-iso.sh'):
                    self.assertEqual(self.wrapper(entry).returncode, 1)
                self.assertEqual(target.read_bytes(), b'unchanged')
                self.repo.lock_path.unlink()

    def test_wrapper_handoff_keeps_lock_and_resource_argv(self):
        self.copy_wrappers()
        body = ('"$TEST_PYTHON" -I "$TEST_CTL" prepare-validation >/dev/null 2>&1; '
                '[[ $? == 1 ]] || return 79; '
                '[[ "$1 $2 $3 $4" == "time-machine -C channels.guix --max-jobs=2" ]] || return 80; '
                '[[ "$5" == --cores=3 ]] || return 81; return 78;')
        result = self.wrapper('build.sh', arguments=('--pinned','--jobs','2','--cores','3'),
                              environment={'TEST_PYTHON':sys.executable,
                                           'TEST_CTL':str(self.root/'securityopsctl')}, guix_body=body)
        self.assertEqual(result.returncode, 78, result.stdout+result.stderr)
        self.prepare()

    def test_image_wrapper_limits_discovery_in_both_guix_branches(self):
        self.copy_wrappers()
        capture = ('"$TEST_PYTHON" -I -c '
                   "'import json,os,sys; print(json.dumps([os.getcwd(),sys.argv[1:]]), file=sys.stderr)' "
                   '"$@"; return 78;')
        resources = ['--cores=3', '--max-jobs=1', '--cores=4']
        cache = '--substitute-urls=https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org'
        for pinned in (False, True):
            with self.subTest(pinned=pinned):
                arguments = (('--pinned',) if pinned else ()) + (
                    '--cores', '3', '--jobs', '1', '--cores', '4')
                result = self.wrapper('build.sh', arguments=arguments,
                                      environment={'TEST_PYTHON': sys.executable}, guix_body=capture)
                self.assertEqual(result.returncode, 78, result.stdout + result.stderr)
                captured = [json.loads(line) for line in result.stderr.splitlines() if line.startswith('[')]
                self.assertEqual(len(captured), 1)
                inner = ['repl', '-q', '-L', str(self.root), '--',
                         str(self.root / 'securityops/build-image.scm'), str(self.root), *resources]
                expected = (['time-machine', '-C', 'channels.guix', *resources,
                             cache, '--fallback', '--'] if pinned else []) + inner
                self.assertEqual(captured[0], [str(self.root), expected])
                self.assertFalse(list(self.repo.out_dir.glob('*.iso')))
                self.prepare()  # The failing child released its lock.

    def test_wrapper_accepts_cli_inherited_fd_without_unlocking_parent(self):
        self.copy_wrappers()
        path = self.prepare()
        with path.open('r+b') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.wrapper('build.sh', environment={
                'SECURITYOPS_ISO_LOCK_HELD':'1', 'SECURITYOPS_ISO_LOCK_FD':str(held.fileno())},
                pass_fds=(held.fileno(),))
            self.assertEqual(result.returncode, 78, result.stdout+result.stderr)
            self.assertEqual(self.cli('prepare-validation').returncode, 1)
        self.prepare()

    def test_signal_after_exec_releases_lock_without_guardian_process(self):
        wrapper = self.root/'build.sh'
        wrapper.write_text('#!' + shutil.which('bash') + '\nexec "' + sys.executable
                           + '" -I -c \'import signal; print("ready", flush=True); signal.pause()\'\n')
        wrapper.chmod(0o700)
        with subprocess.Popen([sys.executable, '-I', str(self.root/'securityopsctl'),
                               '_build-lock','build.sh'], env={'PATH':'/nonexistent'},
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True) as child:
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), 'exec child did not become ready')
                self.assertEqual(child.stdout.readline(), b'ready\n')
                self.assertEqual(self.cli('prepare-validation').returncode, 1)
                child.send_signal(signal.SIGTERM)
                child.communicate(timeout=5)
                self.assertEqual(child.returncode, -signal.SIGTERM)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=5)
        self.prepare()

    def test_internal_dispatch_rejects_arbitrary_executable_and_fd(self):
        for args in (('_build-lock','/bin/true'), ('_build-lock','check','-1'),
                     ('_build-lock','check','9;false'), ('_build-lock','check','99999')):
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args).returncode, 1)
        self.assertFalse(self.repo.lock_path.exists())

    def test_exec_failure_releases_lock(self):
        # The allowlisted wrapper is intentionally absent; exec must fail
        # without leaving a lock holder or accepting an arbitrary alternative.
        result = self.cli('_build-lock','build.sh')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.prepare()


if __name__ == '__main__':
    unittest.main()
