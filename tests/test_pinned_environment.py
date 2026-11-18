# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d12baba6f8c85c65a07bc0391d6802bf owner="Cristian Cezar Mois\u00e9s"
"""Pinned evaluator boundary tests, not channel-authentication evidence."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'tools/validation/securityops-validate'
HELPER = ROOT / 'tools/validation/pinned-guix.scm'


class PinnedEnvironmentTests(unittest.TestCase):
    def setUp(self):
        loader = importlib.machinery.SourceFileLoader('pinned_evaluator_test', str(ENTRY))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.e = importlib.util.module_from_spec(spec)
        loader.exec_module(self.e)
        temp = tempfile.TemporaryDirectory(prefix='securityops-pinned-test-')
        self.addCleanup(temp.cleanup)
        self.context = Path(temp.name)

    def api(self, name):
        function = getattr(self.e, name, None)
        self.assertTrue(callable(function), 'missing pinned boundary: ' + name)
        return function

    def test_invocation_preserves_old_options_and_rejects_ambiguity(self):
        parse = self.api('invocation')
        profile = '/gnu/store/' + '0' * 32 + '-profile'
        self.assertEqual(parse(['quick']), ('quick', None, False))
        self.assertEqual(parse(['full', '--pinned-guix']), ('full', None, True))
        self.assertEqual(parse(['quick', '--pinned-guix', '--check-tools-profile', profile]),
                         ('quick', Path(profile), True))
        for args in ([], ['--pinned-guix', 'quick'], ['quick', '--pinned-guix', '--pinned-guix'],
                     ['quick', '--pinned-guix', profile],
                     ['full', '--check-tools-profile', profile, '--pinned-guix']):
            with self.subTest(args=args), self.assertRaises(self.e.Blocked):
                parse(args)

    def test_result_rejects_malformed_missing_and_aliased_files(self):
        read = self.api('pinned_result')
        result = self.context / 'profile'
        with self.assertRaises(self.e.Blocked):
            read(self.context)
        for data in (b'', b'/tmp/profile\n', b'\xff', b'x' * 1025,
                     b'/gnu/store/' + b'0' * 32 + b'-profile\nextra\n'):
            result.write_bytes(data)
            result.chmod(0o600)
            with self.subTest(data=data[:80]), self.assertRaises(self.e.Blocked):
                read(self.context)
        result.unlink()
        other = self.context / 'other'
        other.write_bytes(b'never accepted')
        other.chmod(0o600)
        for kind in ('symlink', 'hardlink', 'fifo'):
            if kind == 'symlink':
                result.symlink_to(other)
            elif kind == 'hardlink':
                os.link(other, result)
            else:
                os.mkfifo(result, 0o600)
            with self.subTest(kind=kind), self.assertRaises(self.e.Blocked):
                read(self.context)
            result.unlink()

    def helper(self, expected='(current-channels)', *, extra=()):
        self.assertTrue(HELPER.is_file(), 'missing Scheme identity verifier')
        guix = shutil.which('guix')
        self.assertIsNotNone(guix, 'Guix is required; no passing capability skip')
        channels = self.context / 'channels.guix'
        channels.write_text('(use-modules (guix channels) (guix describe))\n' + expected + '\n')
        return subprocess.run([guix, 'repl', '-q', '--', str(HELPER), str(channels),
                               str(self.context / 'profile'), *extra],
                              cwd=self.context, capture_output=True, timeout=30)

    def test_scheme_verifies_actual_profile_and_writes_private_result(self):
        run = self.helper()
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        read = self.api('pinned_result')
        profile, record = read(self.context)
        self.assertEqual(profile.parent, Path('/gnu/store'))
        self.assertEqual(record['profile'], str(profile))
        self.assertEqual(record['manifest_sha256'], self.e.digest((profile/'manifest').read_bytes()))
        self.assertFalse(record['upstream_authentication_claimed'])
        self.assertEqual((self.context/'profile').stat().st_mode & 0o777, 0o600)
        (self.context/'profile').chmod(0o644)
        with self.assertRaises(self.e.Blocked):
            read(self.context)

    def test_scheme_rejects_every_channel_identity_field_and_cardinality(self):
        for expression in ('(cdr (current-channels))',
                           '(append (current-channels) (current-channels))',
                           "(cons (channel (inherit (car (current-channels))) (name 'fixture)) "
                           '(cdr (current-channels)))',
                           *('(cons (channel (inherit (car (current-channels))) (' + field +
                             ' "' + value + '")) (cdr (current-channels)))'
                             for field, value in (('commit', '0'*40), ('url', 'https://invalid.example'),
                                                  ('branch', 'invalid-fixture-branch'))),
                           '(cons (channel (inherit (car (current-channels))) (introduction #f)) '
                           '(cdr (current-channels)))'):
            with self.subTest(expression=expression):
                run = self.helper(expression)
                self.assertNotEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn(b'PINNED_CHANNEL_MISMATCH', run.stderr)
                self.assertFalse((self.context/'profile').exists())

    def test_scheme_never_overwrites_result_or_accepts_extra_arguments(self):
        result = self.context/'profile'
        result.write_bytes(b'existing private evidence\n')
        result.chmod(0o600)
        run = self.helper()
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(result.read_bytes(), b'existing private evidence\n')
        result.unlink()
        run = self.helper(extra=('unexpected',))
        self.assertNotEqual(run.returncode, 0)
        self.assertFalse(result.exists())

    def test_resolver_binds_copies_rejects_source_change_and_never_falls_back(self):
        resolve = self.api('resolve_pinned')
        source = self.context/'source'
        private = self.context/'private'
        private.mkdir(mode=0o700)
        names = ['channels.guix', 'tools/validation/pinned-guix.scm']
        for name in names:
            target = source/name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'public inert source fixture\n')
        calls = []
        def run(name, argv, **kwargs):
            calls.append((name, argv, kwargs))
            self.assertEqual(argv[:3], ['/bootstrap/guix', 'time-machine', '-C'])
            self.assertNotIn('--disable-authentication', argv)
            self.assertEqual(argv[3], str(private/'channels.guix'))
            self.assertEqual(Path(argv[3]).read_bytes(), (source/'channels.guix').read_bytes())
            self.assertEqual(Path(argv[-3]).read_bytes(), (source/names[1]).read_bytes())
            self.assertEqual(argv[-2:], [str(private/'channels.guix'), str(private/'profile')])
            self.assertEqual(kwargs['seconds'], 600)
        expected = (Path('/inert/fixture/profile'), {'upstream_authentication_claimed':False})
        with mock.patch.object(self.e, 'pinned_result', return_value=expected) as result:
            profile, record = resolve(source, set(names), '/bootstrap/guix', run, private)
            self.assertEqual(profile, expected[0])
            self.assertEqual(len(calls), 1)
            self.assertEqual(record['inputs']['channels.guix']['sha256'],
                             self.e.digest((source/'channels.guix').read_bytes()))
            result.assert_called_once_with(private)
        for mode in ('failure', 'source-change', 'copy-change'):
            attempt = self.context/mode
            attempt.mkdir(mode=0o700)
            def faulty(*args, **kwargs):
                if mode == 'failure':
                    raise self.e.Blocked('CHECK_FAIL')
                target = source/'channels.guix' if mode == 'source-change' else attempt/'channels.guix'
                target.write_bytes(('changed fixture ' + mode).encode())
            with self.subTest(mode=mode), mock.patch.object(self.e, 'pinned_result') as result:
                with self.assertRaises(self.e.Blocked):
                    resolve(source, set(names), '/bootstrap/guix', faulty, attempt)
                result.assert_not_called()


if __name__ == '__main__':
    unittest.main()
