# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=158ed6fbf851566997f80fdb7924d25b owner="Cristian Cezar Mois\u00e9s"
"""Real local evaluator boundaries; synthetic inputs never approve the OS."""
import ast
import contextlib
import fcntl
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'tools/validation/securityops-validate'


class EvaluatorTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(ENTRY.is_file(), 'required evaluator is absent')
        loader = importlib.machinery.SourceFileLoader('evaluator_under_test', str(ENTRY))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.e = importlib.util.module_from_spec(spec)
        loader.exec_module(self.e)
        self.temp = tempfile.TemporaryDirectory(prefix='securityops-evaluator-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_child(self, code, **limits):
        return self.e.run_bounded([sys.executable, '-I', '-B', '-c', code],
                                 self.root, {'PATH':str(Path(sys.executable).parent)}, **limits)

    def shell_syntax_fixture(self, broken=None):
        # Execute the real dispatch AST, not a replica of its command builder.
        # Bash really parses bounded inert fixtures; ShellCheck is an argv-only
        # boundary here, not evidence of an installed ShellCheck or Guix.
        bash = shutil.which('bash')
        if bash is None:
            self.fail('Bash is required for syntax regression tests')
        for index, name in enumerate(self.e.SCRIPTS):
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('if true; then\n' if index == broken else
                            'printf unexpected > executed\nexit 71\n')
        tree = ast.parse(ENTRY.read_text(encoding='utf-8'))
        main = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        loops = [node for node in ast.walk(main) if isinstance(node, ast.For)
                 and isinstance(node.iter, ast.Tuple)
                 and {'bash', 'shellcheck'} <= {
                     value.value for value in ast.walk(node.iter)
                     if isinstance(value, ast.Constant) and isinstance(value.value, str)}]
        self.assertEqual(len(loops), 1, 'shell dispatch must remain testable')
        calls = self.syntax_calls = []
        environment = {'PATH':str(Path(bash).parent)}

        def run(name, argv, *, cwd, env):
            calls.append((name, list(argv)))
            self.assertEqual((cwd, env), (self.root, environment))
            if argv[0] == '/fixture/shellcheck':
                return b''
            self.assertEqual(argv[0], bash)
            row, data = self.e.run_bounded(argv, cwd, env, seconds=5, limit=4096)
            self.assertTrue(row['cleanup_complete'])
            if row['status'] != 'PASS':
                self.assertEqual(row['returncode'], 2)
                raise self.e.Blocked('CHECK_'+row['status'])
            return data

        namespace = {'run':run, 'label':'a', 'SCRIPTS':self.e.SCRIPTS,
                     'tools':{'bash':{'path':bash},
                              'shellcheck':{'path':'/fixture/shellcheck'}},
                     'source':self.root, 'fresh_env':environment}
        program = ast.Module(body=[loops[0]], type_ignores=[])
        exec(compile(ast.fix_missing_locations(program), str(ENTRY), 'exec'), namespace)
        return calls

    def test_bash_syntax_dispatch_parses_every_script_without_execution(self):
        calls = self.shell_syntax_fixture()
        self.assertEqual(len(calls), 6)
        self.assertEqual([name for name, _ in calls],
                         ['a-bash-'+str(index) for index in range(1,6)]+['a-shellcheck'])
        self.assertEqual([argv[1:] for _, argv in calls[:5]],
                         [['-n', name] for name in self.e.SCRIPTS])
        self.assertEqual(calls[-1][1], ['/fixture/shellcheck', *self.e.SCRIPTS])
        self.assertFalse((self.root/'executed').exists())

    def test_bash_syntax_failure_in_each_position_stops_before_shellcheck(self):
        for broken in range(5):
            with self.subTest(script=self.e.SCRIPTS[broken]):
                with self.assertRaisesRegex(self.e.Blocked, 'CHECK_FAIL'):
                    self.shell_syntax_fixture(broken=broken)
                self.assertFalse(any(argv[0] == '/fixture/shellcheck'
                                     for _, argv in self.syntax_calls))
                self.assertFalse((self.root/'executed').exists())

    def test_safe_source_read_and_hash_binding(self):
        (self.root/'input.scm').write_bytes(b'(fixture)\n')
        actual = self.e.admit(self.root, ['input.scm'], {'input.scm'})
        self.assertEqual(actual['input.scm']['sha256'], hashlib.sha256(b'(fixture)\n').hexdigest())
        (self.root/'input.scm').write_bytes(b'(changed)\n')
        with self.assertRaises(self.e.Blocked):
            self.e.verify(self.root, actual)

    def test_selected_untracked_is_blocked_before_read(self):
        with self.assertRaisesRegex(self.e.Blocked, 'UNTRACKED'):
            self.e.admit(self.root, ['missing.scm'], set())

    def test_absolute_traversal_control_and_duplicate_paths_rejected(self):
        for names in (['/tmp/x'], ['../x'], ['a/../x'], ['a//x'], ['a\nx'], ['x','x'], ['.']):
            with self.subTest(names=names), self.assertRaises(self.e.Blocked):
                self.e.admit(self.root, names, set(names))

    def test_leaf_and_parent_symlinks_and_hardlinks_rejected(self):
        (self.root/'real').mkdir()
        (self.root/'real/x').write_text('fixture')
        (self.root/'alias').symlink_to('real', target_is_directory=True)
        (self.root/'link').symlink_to('real/x')
        os.link(self.root/'real/x', self.root/'hard')
        for name in ('alias/x','link','hard'):
            with self.subTest(name=name), self.assertRaises(self.e.Blocked):
                self.e.safe_read(self.root, name)

    def test_oversized_source_rejected(self):
        (self.root/'large').write_bytes(b'x'*65)
        with self.assertRaises(self.e.Blocked):
            self.e.safe_read(self.root, 'large', limit=64)

    def test_bootstrap_missing_metadata_cannot_pass(self):
        with self.assertRaises(self.e.Blocked):
            self.e.bootstrap(self.root, set())

    def test_process_success_hashes_but_does_not_retain_output(self):
        row, output = self.run_child("print('synthetic-output')")
        self.assertEqual(row['status'], 'PASS')
        self.assertEqual(row['returncode'], 0)
        self.assertEqual(row['output_sha256'], hashlib.sha256(b'synthetic-output\n').hexdigest())
        self.assertEqual(output, b'')
        self.assertNotIn('synthetic-output', json.dumps(row))

    def test_nonzero_process_cannot_pass(self):
        row, _ = self.run_child('raise SystemExit(7)')
        self.assertEqual((row['status'], row['returncode']), ('FAIL',7))

    def test_timeout_is_blocked_and_cleaned(self):
        row, _ = self.run_child('import time; time.sleep(20)', seconds=.15)
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertEqual(row['reason'], 'TIMEOUT')
        self.assertTrue(row['cleanup_complete'])

    def test_output_limit_is_blocked_even_for_zero_exit(self):
        row, output = self.run_child("print('x'*65536)", limit=1024, capture=True)
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertEqual(row['reason'], 'OUTPUT_LIMIT')
        self.assertLessEqual(len(output),1024)

    def test_background_descendant_is_not_success(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'])"
        row, _ = self.run_child(code, seconds=2)
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertEqual(row['reason'], 'DESCENDANTS')
        self.assertTrue(row['cleanup_complete'])

    def test_signal_cancellation_reaps_owned_group(self):
        code = 'import os,signal,time; os.kill(os.getppid(),signal.SIGINT); time.sleep(20)'
        row, _ = self.run_child(code)
        self.assertEqual((row['status'],row['reason']),('BLOCKED','CANCELLED'))
        self.assertTrue(row['cleanup_complete'])

    def test_guard_failure_prevents_execution(self):
        row, _ = self.run_child('raise SystemExit(0)', guard=lambda:False)
        self.assertEqual((row['status'],row['reason']),('BLOCKED','RESOURCE'))
        self.assertIsNone(row['returncode'])

    def test_worker_skip_error_and_empty_suite_block(self):
        for changed in ({'skipped':1}, {'errors':1}, {'tests':0}, {'check':'other'}):
            counts = {'check':'unittest','tests':2,'failures':0,'errors':0,'skipped':0}
            counts.update(changed)
            self.assertNotEqual(self.e.test_status(counts), 'PASS')
        self.assertEqual(self.e.test_status({'check':'unittest','tests':2,'failures':0,'errors':0,'skipped':0}), 'PASS')

    def test_worker_malformed_counts_rejected(self):
        for value in (None, [], {}, {'check':'unittest','tests':True,'failures':0,'errors':0,'skipped':0}):
            self.assertEqual(self.e.test_status(value), 'BLOCKED')

    def test_existing_lock_contention_is_preserved(self):
        import fcntl
        (self.root/'out').mkdir()
        path = self.root/'out/.iso-build.lock'
        path.touch(mode=0o600)
        inode = path.stat().st_ino
        with path.open('rb') as held:
            fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(self.e.Blocked):
                with self.e.build_lock(self.root):
                    self.fail('contended lock admitted')
        self.assertEqual(path.stat().st_ino,inode)

    def test_private_state_rejects_symlink_and_open_permissions(self):
        (self.root/'unsafe').mkdir(mode=0o755)
        (self.root/'unsafe').chmod(0o755)  # Independent of the evaluator's restrictive umask.
        with self.assertRaises(self.e.Blocked):
            self.e.private_dir(self.root/'unsafe')
        (self.root/'alias').symlink_to(self.root/'unsafe', target_is_directory=True)
        with self.assertRaises(self.e.Blocked):
            self.e.private_dir(self.root/'alias')

    def test_missing_tool_is_blocked_not_shell_fallback(self):
        with self.assertRaises(self.e.Blocked):
            self.e.immutable_tool(self.root/'missing')

    def test_lock_parent_alias_and_missing_lock_block(self):
        with self.assertRaises(self.e.Blocked):
            with self.e.build_lock(self.root):
                self.fail('missing lock admitted')
        (self.root/'real-out').mkdir()
        (self.root/'real-out/.iso-build.lock').touch(mode=0o600)
        (self.root/'out').symlink_to('real-out', target_is_directory=True)
        with self.assertRaises(self.e.Blocked):
            with self.e.build_lock(self.root):
                self.fail('aliased lock admitted')

    def test_real_worker_results_and_process_precedence(self):
        cases = (
            ('pass', 'self.assertTrue(True)', 0, 'PASS'),
            ('fail', 'self.fail("synthetic failure")', 1, 'FAIL'),
            ('error', 'raise ValueError("synthetic error")', 1, 'FAIL'),
            ('skip', 'self.skipTest("synthetic skip")', 1, 'BLOCKED'),
            ('empty', None, 1, 'BLOCKED'))
        for label, body, expected_rc, expected_status in cases:
            with self.subTest(label=label):
                source = self.root/label
                (source/'tests').mkdir(parents=True)
                if body is not None:
                    (source/'tests/test_synthetic.py').write_text(
                        'import unittest\nclass Synthetic(unittest.TestCase):\n'
                        '    def test_case(self):\n        '+body+'\n')
                row, _ = self.e.run_bounded([sys.executable, '-I', '-B',
                    str(ENTRY.parent/'test-worker.py'), str(source), str(source/'result.json')],
                    source, {'PATH':str(Path(sys.executable).parent)})
                self.assertEqual(row['returncode'], expected_rc)
                counts = json.loads((source/'result.json').read_text())
                self.assertEqual(self.e.worker_status(row, counts), expected_status)
                blocked = dict(row, status='BLOCKED', reason='TIMEOUT')
                self.assertEqual(self.e.worker_status(blocked, counts), 'BLOCKED')
                if label == 'pass':
                    self.assertEqual(self.e.worker_status(dict(row, status='FAIL', returncode=7), counts), 'FAIL')

    def test_context_retained_on_cleanup_uncertainty(self):
        checks = []
        with self.e.owned_context(self.root, 'clean', checks) as clean:
            (clean/'fixture').write_text('fixture')
        self.assertFalse(clean.exists())
        with self.e.owned_context(self.root, 'uncertain', checks) as preserved:
            checks.append({'cleanup_complete':False})
        self.assertTrue(preserved.is_dir())

    def test_real_selector_prunes_state_but_exposes_untracked_inputs(self):
        import shutil
        guile = shutil.which('guile')
        self.assertIsNotNone(guile, 'required Guile unavailable; never skip')
        (self.root/'visible.scm').write_text('(fixture)')
        (self.root/'out').mkdir()
        (self.root/'out/hidden.scm').write_text('(excluded)')
        (self.root/'.dsh').mkdir()
        (self.root/'.dsh/hidden.scm').write_text('(excluded)')
        (self.root/'ignored-but-selected.scm').write_text('(untracked)')
        row, data = self.e.run_bounded([guile, '--no-auto-compile', '-L', str(ROOT),
            '-s', str(ENTRY.parent/'source-check.scm'), str(self.root)], self.root,
            dict(os.environ, GUILE_AUTO_COMPILE='0'), capture=True)
        self.assertEqual(row['status'], 'PASS')
        names = json.loads(data)
        self.assertEqual(names, ['ignored-but-selected.scm', 'visible.scm'])
        with self.assertRaisesRegex(self.e.Blocked, 'UNTRACKED'):
            self.e.admit(self.root, names, {'visible.scm'})

    def test_count_protocol_rejects_extra_fields_not_subtest_failures(self):
        counts = dict(check='unittest', tests=1, failures=2, errors=0, skipped=0)
        # Multiple failed subtests legitimately outnumber testsRun.
        self.assertEqual(self.e.test_status(counts), 'FAIL')
        self.assertEqual(self.e.test_status(dict(counts, unexpected='fixture')), 'BLOCKED')

    def test_source_mode_changes_invalidate_snapshot(self):
        path = self.root/'input.scm'
        path.write_text('(fixture)')
        path.chmod(0o600)
        inventory = self.e.admit(self.root, ['input.scm'], {'input.scm'})
        path.chmod(0o700)
        with self.assertRaisesRegex(self.e.Blocked, 'SOURCE_CHANGED'):
            self.e.verify(self.root, inventory)

    def test_observation_exception_restores_handlers_and_blocks_cleanup(self):
        original = {s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        with mock.patch.object(self.e, 'members', side_effect=ValueError('synthetic observation')):
            row, _ = self.run_child('pass')
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertFalse(row['cleanup_complete'])
        self.assertEqual({s:signal.getsignal(s) for s in original}, original)

    def test_guard_exception_and_uncertain_cleanup_retain_context(self):
        checks = []
        with self.e.owned_context(self.root, 'uncertain', checks) as context:
            with mock.patch.object(self.e, 'members', side_effect=ValueError('synthetic observation')):
                guard = mock.Mock(side_effect=[True, RuntimeError('synthetic guard')])
                row, _ = self.run_child('import time;time.sleep(20)', guard=guard)
            checks.append(row)
        self.assertEqual(row['status'], 'BLOCKED')
        self.assertFalse(row['cleanup_complete'])
        self.assertTrue(context.is_dir())

    def test_reaped_anchor_never_signals_reused_group(self):
        real_waitid = os.waitid
        def reap_then_lose(which, pid, flags):
            found = real_waitid(which, pid, flags)
            if found is not None:
                os.waitpid(pid, 0)
                raise ChildProcessError('synthetic reaper')
            return found
        with mock.patch.object(self.e.os, 'waitid', side_effect=reap_then_lose):
            with mock.patch.object(self.e.os, 'killpg') as kill:
                row, _ = self.run_child('pass')
        self.assertFalse(row['cleanup_complete'])
        self.assertEqual(row['status'], 'BLOCKED')
        kill.assert_not_called()

    def test_cancellation_during_output_drain(self):
        code = 'import os,signal,time; os.write(1,b"x"*4096); os.kill(os.getppid(),signal.SIGTERM); time.sleep(20)'
        row, _ = self.run_child(code)
        self.assertEqual((row['status'],row['reason']), ('BLOCKED','CANCELLED'))
        self.assertTrue(row['cleanup_complete'])

    def auxiliary_api(self, name):
        value = getattr(self.e, name, None)
        self.assertTrue(callable(value), 'missing auxiliary-profile boundary: '+name)
        return value

    def test_auxiliary_option_is_explicit_and_strict(self):
        parse = self.auxiliary_api('options')
        profile = '/gnu/store/'+'0'*32+'-profile'
        self.assertEqual(parse(['quick']), ('quick',None))
        self.assertEqual(parse(['full','--check-tools-profile',profile]), ('full',Path(profile)))
        for args in ([], ['quick',profile], ['quick','--check-tools-profile'],
                     ['quick','--check-tools-profile',profile,'extra'], ['build'],
                     ['full','--profile',profile]):
            with self.subTest(args=args), self.assertRaises(self.e.Blocked):
                parse(args)

    def test_auxiliary_manifest_accepts_only_minimal_data(self):
        parse = self.auxiliary_api('check_tools_manifest')
        item = '/gnu/store/'+'0'*32+'-shellcheck-0.10.0'
        data = ('; Generated fixture, not authority.\n(manifest (version 4) '
                '(packages (("shellcheck" "0.10.0" "out" "'+item+'"))))\n').encode()
        self.assertEqual(parse(data), ('0.10.0',Path(item)))
        for bad in (data+b'(extra)', data.replace(b'"shellcheck"',b'"bash"'),
                    data.replace(b'"out"',b'"debug"'), data.replace(b'(version 4)',b'(version 3)'),
                    data.replace(b'"0.10.0"',b'#.(error "never read")'),
                    data.replace(b'))))',b') ("other" "1" "out" "x"))))'),
                    data.replace(b'-shellcheck-0.10.0',b'-shellcheck-0.9.0'),
                    data+b'\x00', b'x'*65537):
            with self.subTest(bad=bad[:80]), self.assertRaises(self.e.Blocked):
                parse(bad)

    def test_auxiliary_store_path_rejects_noncanonical_spelling(self):
        parse = self.auxiliary_api('store_item')
        valid = '/gnu/store/'+'0'*32+'-profile'
        self.assertEqual(parse(valid), Path(valid))
        for path in ('relative', valid+'/', valid+'/../x', '/gnu//store/'+valid.rsplit('/',1)[1],
                     valid+'\n', '/gnu/store/not-a-hash-profile', valid+'/bin/shellcheck'):
            with self.subTest(path=path), self.assertRaises(self.e.Blocked):
                parse(path)

    def test_auxiliary_mutable_profile_rejected_before_query(self):
        admit = self.auxiliary_api('check_tools_profile')
        target = self.root/'fake-profile'
        target.mkdir()
        alias = self.root/'alias'
        alias.symlink_to('/gnu/store/9qcaradm653pzzf32771aahj8s6pycfc-profile')
        def forbidden(*args, **kwargs):
            self.fail('unvalidated profile reached Guix query')
        for path in (target, alias):
            with self.subTest(path=path), self.assertRaises(self.e.Blocked):
                admit(path, '/unused/guix', forbidden)

    def test_auxiliary_records_require_exact_manifest_and_closure_match(self):
        check = self.auxiliary_api('check_tools_records')
        profile = Path('/gnu/store/'+'0'*32+'-profile')
        item = Path('/gnu/store/'+'1'*32+'-shellcheck-0.10.0')
        listing = ('shellcheck\t0.10.0\tout\t'+str(item)+'\n').encode()
        closure = (str(item)+'\n'+str(profile)+'\n').encode()
        self.assertEqual(check(profile,'0.10.0',item,listing,closure), sorted([str(item),str(profile)]))
        cases = ((listing*2,closure),(listing.replace(b'0.10.0',b'0.9.0'),closure),
                 (listing.replace(b'out\t',b'debug\t'),closure),
                 (listing, (str(profile)+'\n').encode()), (listing,closure*2),
                 (listing,closure+b'/tmp/mutable\n'), (listing+b'warning\n',closure),
                 (listing,closure+b'\xff'))
        for packages,refs in cases:
            with self.subTest(packages=packages,refs=refs), self.assertRaises(self.e.Blocked):
                check(profile,'0.10.0',item,packages,refs)

    def test_auxiliary_selection_cannot_replace_other_tools(self):
        select = self.auxiliary_api('base_tools')
        first, second = self.root/'first', self.root/'second'
        for profile in (first,second):
            (profile/'bin').mkdir(parents=True)
            for name in ('git','python3','bash','shellcheck','guile','guild','guix'):
                (profile/'bin'/name).write_text('inert selection fixture')
        # Identity validation is a separate, real-file boundary; here isolate
        # selection policy without constructing fake root-owned Store objects.
        with mock.patch.object(self.e, 'immutable_tool', side_effect=lambda p:{'path':str(p)}):
            normal = select((first,second), auxiliary=False)
            auxiliary = select((first,second), auxiliary=True)
        self.assertEqual(set(normal)-set(auxiliary), {'shellcheck'})
        self.assertEqual(auxiliary, {k:v for k,v in normal.items() if k!='shellcheck'})
        self.assertTrue(all(v['path'].startswith(str(first)+'/bin/') for v in auxiliary.values()))

    def test_auxiliary_missing_default_tool_still_blocks(self):
        select = self.auxiliary_api('base_tools')
        profile = self.root/'base'
        (profile/'bin').mkdir(parents=True)
        for name in ('git','python3','bash','guile','guild','guix'):
            (profile/'bin'/name).write_text('inert fixture')
        with mock.patch.object(self.e, 'immutable_tool', side_effect=lambda p:{'path':str(p)}):
            with self.assertRaisesRegex(self.e.Blocked, 'TOOL_UNAVAILABLE_SHELLCHECK'):
                select((profile,), auxiliary=False)

    def test_cli_rejects_invalid_mode_without_traceback(self):
        row,data = self.e.run_bounded([sys.executable,'-I','-B',str(ENTRY),'invalid'],
                                      self.root,{},capture=True,limit=4096)
        self.assertEqual(row['returncode'],2,data.decode())
        self.assertNotIn(b'Traceback',data)
        self.assertFalse((self.root/'.dsh').exists())

    def main_fixture(self, requested, *, failure=None, omit_dispatch=False, change_mode=False,
                     worker_observations=None, worker_fail=False, pinned=False,
                     pinned_failure=None, environment_observations=None,
                     change_pinned_input=False, auxiliary=False):
        """Real main/files/copy/flock; only external commands/tools are synthetic."""
        source = self.root/'project'
        names = sorted(set(self.e.BOOTSTRAP)|{'config.scm','securityopsctl'})
        if pinned:
            names += ['channels.guix', 'tools/validation/pinned-guix.scm']
        if worker_observations is not None:
            names += ['tests/test_probe.py', 'tools/validation/sitecustomize.py']
        for name in names:
            path = source/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text('public inert orchestration fixture\n')
            path.chmod(0o700 if name == 'securityopsctl' else 0o600)
        if worker_observations is not None:
            (source/'tools/validation/test-worker.py').write_bytes((ENTRY.parent/'test-worker.py').read_bytes())
            (source/'tools/validation/sitecustomize.py').write_text(
                'import builtins; builtins.securityops_startup_sentinel = True\n')
            (source/'tests/test_probe.py').write_text('''import builtins, importlib.util, json, os, sys, unittest
from pathlib import Path
class Probe(unittest.TestCase):
    def test_probe(self):
        observed = dict(seed=os.environ.get('PYTHONHASHSEED'),
            hashes=[hash('Security Ops worker'), hash(b'public seed probe')],
            flags={k:getattr(sys.flags,k) for k in ('ignore_environment','no_site','no_user_site','safe_path','dont_write_bytecode')},
            environment_keys=sorted(os.environ), path=sys.path,
            site_loaded='site' in sys.modules,
            startup_sentinel=hasattr(builtins,'securityops_startup_sentinel'),
            ambient_import=importlib.util.find_spec('securityops_ambient_sentinel') is not None,
            user_import=importlib.util.find_spec('securityops_user_sentinel') is not None)
        (Path(os.environ['HOME']).parent/'probe.json').write_text(json.dumps(observed))
''' + ('        self.fail("public worker failure fixture")\n' if worker_fail else ''))
        (source/'out').mkdir()
        lock = source/'out/.iso-build.lock'
        lock.touch(mode=0o600)
        inode = lock.stat().st_ino
        tools = {n:{'path':'/fixture/'+n} for n in
                 ('git','python3','bash','shellcheck','guile','guild','guix')}
        calls = []
        pinned_profile = Path('/fixture-pinned')
        resolved = False
        real_run = self.e.run_bounded
        def command(argv,cwd,environment,**kwargs):
            nonlocal resolved
            data = b''
            row = dict(returncode=0,status='PASS',reason=None,cleanup_complete=True)
            if environment_observations is not None:
                environment_observations.append((list(argv), dict(environment), resolved))
            executable = Path(argv[0]).name
            self.assertEqual(argv[0], str(pinned_profile/'bin'/executable)
                             if resolved and not (auxiliary and executable == 'shellcheck')
                             else '/fixture/'+executable)
            if argv[1:2] == ['time-machine']:
                self.assertFalse(resolved, 'resolver must execute once')
                resolved = True
                if pinned_failure:
                    row.update(pinned_failure)
            elif executable == 'git':
                operation = argv[argv.index('-C')+2:]
                if operation[0] == 'check-ignore':
                    data = b'.dsh/state/probe\n'
                elif operation[0] == 'ls-files':
                    data = ('\0'.join(names)+'\0').encode()
                elif operation[0] == 'rev-parse':
                    data = b'0000000000000000000000000000000000000000\n'
                else:
                    self.assertEqual(operation,['diff','--check'])
            elif executable == 'guile':
                if '-s' in argv:
                    if pinned and change_pinned_input:
                        (source/'channels.guix').write_text('changed between resolver and inventory\n')
                    data = b'["config.scm", "securityopsctl"]'
                else:
                    self.assertIn('-c',argv)
            elif len(argv)>3 and argv[-3].endswith('/test-worker.py'):
                if worker_observations is not None:
                    # Only this public miniature worker executes; no Guix
                    # queries or Store operations are delegated by this fixture.
                    home = Path(environment['HOME'])
                    user_site = home/'.local/lib'/('python%d.%d' % sys.version_info[:2])/'site-packages'
                    user_site.mkdir(parents=True)
                    (user_site/'usercustomize.py').write_text(
                        'import builtins; builtins.securityops_startup_sentinel = True\n')
                    (user_site/'securityops_user_sentinel.py').write_text('public = True\n')
                    row,data = real_run([sys.executable,*argv[1:]],cwd,environment,
                                        seconds=5,limit=16384,capture=True)
                    probe = home.parent/'probe.json'
                    if probe.exists():
                        observed = json.loads(probe.read_text())
                        observed['bytecode'] = [str(p) for p in home.parent.rglob('*.pyc')]
                        observed['source'] = str(cwd)
                        worker_observations.append(observed)
                    return row,data
                # Counts are command-protocol fixtures, not an actual test run.
                Path(argv[-1]).write_text(json.dumps(dict(
                    check='unittest',tests=1,failures=0,errors=0,skipped=0)))
            elif argv[-2:] == ['validate','--full']:
                with lock.open('rb') as handle:
                    # A real separately opened exclusive lock would fail if
                    # main still held its quick shared lock across dispatch.
                    fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                calls.append({'argv':argv,'home':environment['HOME'],
                              'seed':environment['PYTHONHASHSEED'],
                              'seconds':kwargs['seconds']})
                if failure is not None and len(calls)==failure[0]:
                    row.update(failure[1])
            else:
                self.assertIn(executable,('python3','bash','shellcheck'))
                if executable=='python3':
                    self.assertIn(argv[-1],('validate','doctor'))
            row.update(bytes=len(data),output_sha256=hashlib.sha256(data).hexdigest(),elapsed_seconds=0)
            return row,data
        main = self.e.main
        if omit_dispatch or change_mode:
            # Fault injection in an isolated function: a future dispatch omission
            # must be caught by completion validation, not just branch tests.
            tree = ast.parse(ENTRY.read_text())
            function = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
            dispatch = next(n for n in ast.walk(function) if isinstance(n,ast.If)
                            and any(isinstance(c,ast.For) for c in n.body)
                            and isinstance(n.test,ast.Compare)
                            and any(isinstance(c,ast.Constant) and c.value=='full'
                                    for c in n.test.comparators))
            if omit_dispatch:
                dispatch.test = ast.Constant(False)
            else:
                parent = next(n for n in ast.walk(function)
                              if dispatch in getattr(n,'body',[]))
                parent.body.insert(parent.body.index(dispatch),ast.Assign(
                    targets=[ast.Name(dispatch.test.left.id,ast.Store())],
                    value=ast.Constant('quick')))
            namespace = dict(vars(self.e))
            exec(compile(ast.fix_missing_locations(ast.Module(body=[function],type_ignores=[])),
                         str(ENTRY),'exec'),namespace)
            main = namespace['main']
            namespace['run_bounded'] = command
            namespace['base_tools'] = lambda *a,**k:tools
        mask = os.umask(0o077)
        try:
            def select(profiles, **kwargs):
                if profiles[0] == pinned_profile:
                    return {n:{'path':str(pinned_profile/'bin'/n)} for n in tools
                            if not (kwargs.get('auxiliary') and n == 'shellcheck')}
                return tools
            with mock.patch.object(self.e,'base_tools',side_effect=select), \
                 mock.patch.object(self.e,'pinned_result',return_value=(pinned_profile, {})), \
                 mock.patch.object(self.e,'check_tools_profile',return_value=(tools['shellcheck'],{})), \
                 mock.patch.object(self.e,'run_bounded',side_effect=command), \
                 contextlib.redirect_stdout(io.StringIO()):
                args = [requested]+(['--pinned-guix'] if pinned else [])
                if auxiliary:
                    args += ['--check-tools-profile','/gnu/store/'+'0'*32+'-profile']
                code = main(source,args)
        finally:
            os.umask(mask)
        receipts = list((source/'.dsh/state').glob('validation-*/result.json'))
        self.assertEqual(len(receipts),1)
        report = json.loads(receipts[0].read_text())
        self.assertFalse(report['production_gate_approved'])
        self.assertFalse(report['iso_release_allowed'])
        self.assertEqual(lock.stat().st_ino,inode)
        self.assertFalse(any(p.is_dir() and p.name.startswith(('a-','b-','full-'))
                             for p in receipts[0].parent.iterdir()))
        return code,report,calls

    def test_pinned_environment_reaches_every_ab_and_full_command(self):
        observations = []
        code,report,calls = self.main_fixture('full', pinned=True,
                                             environment_observations=observations)
        self.assertEqual((code, report['status']), (0, 'PASS'))
        self.assertEqual(len(calls), 2)
        self.assertEqual(sum(argv[1:2] == ['time-machine'] for argv,_,_ in observations), 1)
        self.assertNotEqual(report['bootstrap_tools'], report['tools'])
        self.assertIn('channels.guix', report['pinned_guix']['inputs'])
        after = [(argv,env) for argv,env,resolved in observations if resolved]
        self.assertTrue(after)
        for argv,env in after:
            with self.subTest(argv=argv):
                self.assertTrue(argv[0].startswith('/fixture-pinned/bin/'))
                for key in ('PATH', 'GUILE_LOAD_PATH', 'GUILE_LOAD_COMPILED_PATH'):
                    entries = env[key].split(':')
                    self.assertEqual(len(entries), 2)
                    self.assertTrue(entries[0].startswith('/fixture-pinned/'))
                    self.assertTrue(entries[1].startswith(str(Path('/run/current-system/profile').resolve())+'/'))
        self.assertEqual({env['PYTHONHASHSEED'] for _,env in after}, {'6134','4921','8123','9731'})

    def test_pinned_failure_cannot_fall_back_to_personal_profile(self):
        code,report,calls = self.main_fixture('full', pinned=True,
            pinned_failure=dict(status='FAIL',returncode=1))
        self.assertEqual((code,report['status']), (1,'FAIL'))
        self.assertEqual(report['checks'][-1]['check'], 'pinned-guix-resolve')
        self.assertNotIn('a-tests', report)
        self.assertEqual(calls, [])

    def test_pinned_environment_preserves_separate_shellcheck_admission(self):
        observations = []
        code,report,_ = self.main_fixture('quick', pinned=True, auxiliary=True,
                                         environment_observations=observations)
        self.assertEqual((code,report['status']), (0,'PASS'))
        self.assertEqual(report['tools']['shellcheck']['path'], '/fixture/shellcheck')
        checks = [env for argv,env,_ in observations if argv[0] == '/fixture/shellcheck']
        self.assertEqual(len(checks), 2)
        self.assertTrue(all(env['PATH'].startswith('/fixture-pinned/bin:') for env in checks))
        self.assertTrue(all('/fixture/' not in env['PATH'] for env in checks))

    def test_pinned_input_cannot_change_between_resolution_and_inventory(self):
        code,report,calls = self.main_fixture('quick', pinned=True, change_pinned_input=True)
        self.assertEqual((code,report['status']), (2,'BLOCKED'))
        self.assertEqual(report['reason'], 'PINNED_INPUT_CHANGED')
        self.assertNotIn('a-tests', report)
        self.assertEqual(calls, [])

    def test_pinned_uncertain_cleanup_cannot_consume_result(self):
        code,report,calls = self.main_fixture('quick', pinned=True,
            pinned_failure=dict(cleanup_complete=False))
        self.assertEqual((code,report['status']), (2,'BLOCKED'))
        self.assertEqual(report['reason'], 'CHECK_CLEANUP')
        self.assertNotIn('pinned_guix', report)
        self.assertEqual(calls, [])

    def test_main_workers_apply_configured_hash_seeds(self):
        observed = []
        code,report,_ = self.main_fixture('quick',worker_observations=observed)
        self.assertEqual((code,report['status']),(0,'PASS'))
        self.assertEqual([o['seed'] for o in observed],['6134','4921'])
        for item in observed:
            with self.subTest(seed=item['seed']):
                self.assertEqual(item['flags']['ignore_environment'],0)
                reference = []
                for _ in range(2):
                    row,data = self.e.run_bounded([sys.executable,'-s','-P','-B','-S','-c',
                        "import json; print(json.dumps([hash('Security Ops worker'),hash(b'public seed probe')]))"],
                        self.root,{'PYTHONHASHSEED':item['seed']},seconds=5,limit=4096,capture=True)
                    self.assertEqual(row['status'],'PASS')
                    reference.append(json.loads(data))
                self.assertEqual(reference[0],reference[1])
                self.assertEqual(item['hashes'],reference[0])
        self.assertNotEqual(observed[0]['hashes'],observed[1]['hashes'])

    def test_main_workers_reject_ambient_import_and_startup_influence(self):
        ambient = self.root/'ambient'
        ambient.mkdir()
        for name in ('sitecustomize.py','usercustomize.py','startup.py','securityops_ambient_sentinel.py'):
            (ambient/name).write_text('import builtins; builtins.securityops_startup_sentinel = True\n')
        poisoned = {k:str(ambient) for k in ('PYTHONHOME','PYTHONPATH','PYTHONUSERBASE','LD_LIBRARY_PATH')}
        poisoned.update(PYTHONSTARTUP=str(ambient/'startup.py'),PYTHONINSPECT='1',
                        PYTHONHASHSEED='111',LD_PRELOAD=str(ambient/'absent-fixture.so'))
        observed = []
        with mock.patch.dict(os.environ,poisoned):
            code,report,_ = self.main_fixture('quick',worker_observations=observed)
        self.assertEqual((code,report['status']),(0,'PASS'))
        self.assertEqual(len(observed),2)
        for item in observed:
            with self.subTest(seed=item['seed']):
                self.assertEqual(item['flags'],dict(ignore_environment=0,no_site=1,
                    no_user_site=1,safe_path=True,dont_write_bytecode=1))
                self.assertFalse(item['site_loaded'])
                self.assertFalse(item['startup_sentinel'])
                self.assertFalse(item['ambient_import'])
                self.assertFalse(item['user_import'])
                self.assertEqual(item['bytecode'],[])
                self.assertEqual(set(item['environment_keys']) & set(poisoned),{'PYTHONHASHSEED'})
                self.assertNotIn('',item['path'])
                for unsafe in (str(ambient),item['source'],item['source']+'/tools/validation'):
                    self.assertNotIn(unsafe,item['path'])

    def test_main_real_worker_failure_stops_before_second_pass(self):
        observed = []
        code,report,_ = self.main_fixture('quick',worker_observations=observed,worker_fail=True)
        self.assertEqual((code,report['status']),(1,'FAIL'))
        self.assertEqual(report['reason'],'TEST_FAIL')
        self.assertEqual(len(observed),1)
        self.assertEqual(report['a-tests'],dict(check='unittest',tests=1,failures=1,errors=0,skipped=0))
        self.assertNotIn('b-tests',report)

    def test_full_mode_survives_copy_and_releases_shared_lock(self):
        code,report,calls = self.main_fixture('full')
        self.assertEqual((code,report['status']),(0,'PASS'))
        self.assertEqual([r['check'] for r in report['checks'][-2:]],['full-a','full-b'])
        self.assertEqual(len(calls),2)
        self.assertEqual([c['seed'] for c in calls],['8123','9731'])
        self.assertNotEqual(calls[0]['home'],calls[1]['home'])
        for call in calls:
            self.assertEqual(call['argv'],['/fixture/python3','-I','-B',
                str(self.root/'project/securityopsctl'),'validate','--full'])
            self.assertEqual(call['seconds'],1800)

    def test_quick_never_dispatches_full(self):
        code,report,calls = self.main_fixture('quick')
        self.assertEqual((code,report['status']),(0,'PASS'))
        self.assertEqual(calls,[])

    def test_first_full_failure_stops_before_second(self):
        code,report,calls = self.main_fixture('full',failure=(1,dict(status='FAIL',returncode=77)))
        self.assertEqual((code,report['status']),(1,'FAIL'))
        self.assertEqual(len(calls),1)
        self.assertEqual(report['checks'][-1]['check'],'full-a')

    def test_first_full_cancellation_blocks_second(self):
        code,report,calls = self.main_fixture('full',failure=(1,dict(
            status='BLOCKED',reason='CANCELLED',returncode=-9)))
        self.assertEqual((code,report['status']),(2,'BLOCKED'))
        self.assertEqual(len(calls),1)

    def test_second_full_failure_cannot_pass(self):
        code,report,calls = self.main_fixture('full',failure=(2,dict(status='FAIL',returncode=77)))
        self.assertEqual((code,report['status']),(1,'FAIL'))
        self.assertEqual(len(calls),2)

    def test_omitted_full_dispatch_is_independently_blocked(self):
        code,report,calls = self.main_fixture('full',omit_dispatch=True)
        self.assertEqual((code,report['status']),(2,'BLOCKED'))
        self.assertEqual(report['reason'],'FULL_CHECKS_INCOMPLETE')
        self.assertEqual(calls,[])

    def test_changed_requested_mode_cannot_silently_downgrade_full(self):
        code,report,calls = self.main_fixture('full',change_mode=True)
        self.assertEqual((code,report['status']),(2,'BLOCKED'))
        self.assertEqual(report['reason'],'MODE_CHANGED')
        self.assertEqual(calls,[])

    def test_full_completion_requires_exact_order_and_success(self):
        check = getattr(self.e,'require_full_checks',None)
        self.assertTrue(callable(check),'full completion guard is absent')
        a = dict(check='full-a',status='PASS',returncode=0,cleanup_complete=True)
        b = dict(a,check='full-b')
        check([dict(check='b-whitespace'),a,b])
        invalid = [[],[a],[b],[b,a],[a,a,b],[a,b,a,b],[a,b,dict(check='late')]]
        for change in ({'status':'FAIL'},{'returncode':7},{'returncode':None},
                       {'returncode':False},{'cleanup_complete':False},{'cleanup_complete':1}):
            invalid.append([a,dict(b,**change)])
        for rows in invalid:
            with self.subTest(rows=rows), self.assertRaisesRegex(self.e.Blocked,'FULL_CHECKS_INCOMPLETE'):
                check(rows)

    def assert_installer_fixture_cleanup(self, mode):
        # Exercise the actual historical fixture. Missing cleanup must fail the
        # outer process boundary even when its own assertions pass.
        code = r'''
import runpy, sys
definitions = runpy.run_path(sys.argv[1])
name = 'test_lock_marker_is_bound_to_exact_flock_parent_and_inode'
case = definitions['InstallerCredentialTests'](name)
class InjectedAssertion(AssertionError): pass
class InjectedInterrupt(KeyboardInterrupt): pass
fault = {'assertion': InjectedAssertion, 'interrupt': InjectedInterrupt}.get(sys.argv[2])
if fault is not None:
    def interrupt_assertion(*args, **kwargs):
        raise fault('fixture body injection')
    case.assertNotEqual = interrupt_assertion
try:
    getattr(case, name)()
except (InjectedAssertion, InjectedInterrupt) as error:
    if type(error) is not fault:
        raise
else:
    if fault is not None:
        raise AssertionError('injection point not reached')
print('fixture-clean')
'''
        env = {'PATH':'/run/current-system/profile/bin', 'HOME':str(self.root),
               'TMPDIR':str(self.root), 'LANG':'C.UTF-8', 'LC_ALL':'C.UTF-8'}
        row, output = self.e.run_bounded(
            [sys.executable, '-I', '-B', '-c', code,
             str(ROOT/'tests/test_installer_credentials.py'), mode],
            ROOT, env, seconds=35, capture=True)
        self.assertEqual(row['status'], 'PASS', (row, output))
        self.assertEqual(row['returncode'], 0)
        self.assertTrue(row['cleanup_complete'])
        self.assertEqual(output, b'fixture-clean\n')

    def test_installer_fixture_cleanup_on_success(self):
        self.assert_installer_fixture_cleanup('success')

    def test_installer_fixture_cleanup_on_assertion_failure(self):
        self.assert_installer_fixture_cleanup('assertion')

    def test_installer_fixture_cleanup_on_interrupt(self):
        self.assert_installer_fixture_cleanup('interrupt')


if __name__ == '__main__':
    unittest.main()
