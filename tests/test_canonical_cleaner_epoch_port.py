"""Execute the sealed epoch SQL against a disposable frozen-schema PostgreSQL.

Requires PostgreSQL server binaries and the hash-pinned Product authority checkout.
Missing prerequisites fail rather than silently skip this compatibility contract.
"""
from contextlib import ExitStack
import hashlib
import inspect
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from adcp.cleaner_cutover_control import (
    CanonicalCleanerEpochPort, CleanerEpochTransition, CleanerCutoverControlError,
)
from adcp.postgres_control import SanitizedProcessResult, TypedPostgresError
from adcp.postgres_flyway import FROZEN_MIGRATIONS


class CanonicalCleanerEpochPortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = ExitStack()
        cls.addClassCleanup(cls.resources.close)
        cls.tmp = Path(cls.resources.enter_context(tempfile.TemporaryDirectory(prefix='dl97-pg-')))
        configured = os.environ.get('ADCP_TEST_POSTGRES_BIN')
        cls.bin = Path(configured) if configured else Path(shutil.which('initdb') or '/opt/homebrew/opt/postgresql@18/bin/initdb').parent
        cls.env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': str(cls.tmp)}
        # No inherited PG service, credential, socket, port or database settings.
        cls._process('initdb', '-D', str(cls.tmp / 'data'), '--auth=trust', '--no-locale', '-U', 'dl97_test')
        cls.resources.callback(cls._process, 'pg_ctl', '-D', str(cls.tmp / 'data'), '-m', 'immediate', '-w', 'stop')
        cls._process('pg_ctl', '-D', str(cls.tmp / 'data'), '-l', str(cls.tmp / 'server.log'), '-o', f"-F -k {cls.tmp} -c listen_addresses=''", '-w', 'start')
        migration = next(m for m in FROZEN_MIGRATIONS if m.version == '20260904.102')
        source = Path(os.environ.get('ADCP_TEST_FROZEN_PRODUCT_ROOT', str(Path.home() / 'PropertyAI/worktrees/p0-cleaner-postgres-authority-cutover-01-bi01')))
        ddl = (source / migration.path).read_bytes()
        if hashlib.sha256(ddl).hexdigest() != migration.sha256:
            raise AssertionError('Frozen migration bytes do not match Controller authority')
        # Materialize exact DDL and seed statements, not a handwritten table fixture.
        table = re.findall(r'CREATE TABLE propertyai\.authority_epoch \(.*?\n\);', ddl.decode(), re.S)
        seed = re.findall(r'INSERT INTO propertyai\.authority_epoch\(.*?;', ddl.decode(), re.S)
        if len(table) != 1 or len(seed) != 1:
            raise AssertionError('Frozen epoch DDL extraction must be unambiguous')
        cls.schema = '\n'.join(['CREATE SCHEMA propertyai;', table[0], seed[0]])

    @classmethod
    def _process(cls, program, *args, input=None):
        return subprocess.run([str(cls.bin / program), *args], input=input, capture_output=True, check=True, env=cls.env)

    @classmethod
    def _sql(cls, sql):
        return cls._process('psql', '-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-h', str(cls.tmp), '-U', 'dl97_test', '-d', 'postgres', input=sql.encode()).stdout.decode()

    def setUp(self):
        self._sql('DROP SCHEMA IF EXISTS propertyai CASCADE;' + self.schema)
        self.statements = []
        self.policy = object()
        self.port = CanonicalCleanerEpochPort(policy=self.policy)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('adcp.postgres_control._run_psql', side_effect=self._adapter))
        self.stack.enter_context(patch('adcp.cleaner_cutover_control._run_psql', side_effect=self._adapter))
        self.lease = self.stack.enter_context(patch('adcp.cleaner_cutover_control.revalidate_current_controlled_deployment_lease'))

    def _adapter(self, policy, *, database, stdin_sql, execution_role, read_only=False):
        self.assertIs(policy, self.policy)
        self.assertEqual('propertyai_cleaner_prod', database)
        self.assertEqual('propertyai_dba', execution_role)
        sql = stdin_sql.decode()
        self.statements.append(sql)
        try:
            stdout = self._sql(('BEGIN READ ONLY;' + sql + 'COMMIT;') if read_only else sql)
            return SanitizedProcessResult(0, stdout, '')
        except subprocess.CalledProcessError as error:
            return SanitizedProcessResult(error.returncode, error.stdout.decode(), error.stderr.decode())

    def test_read_exact_frozen_seed_and_scope_lookup(self):
        self._sql("INSERT INTO propertyai.authority_epoch(scope_code,current_epoch) VALUES ('OTHER',99)")
        self.assertEqual(1, self.port.read_current())
        self.assertIn("WHERE scope_code = 'CLEANER_SCHEDULING'", self.statements[0])

    def test_missing_scope_fails_closed(self):
        self._sql("DELETE FROM propertyai.authority_epoch WHERE scope_code='CLEANER_SCHEDULING'")
        with self.assertRaisesRegex(TypedPostgresError, 'CARDINALITY_INVALID'):
            self.port.read_current()

    def test_duplicate_scope_is_structurally_impossible(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self._sql("INSERT INTO propertyai.authority_epoch(scope_code,current_epoch) VALUES ('CLEANER_SCHEDULING',2)")
        self.assertEqual(1, self.port.read_current())

    def test_successor_and_factual_post_update_readback(self):
        self._sql('UPDATE propertyai.authority_epoch SET current_epoch=17')
        self.assertEqual(18, self.port.advance(CleanerEpochTransition(17,18)))
        self.assertEqual(18, self.port.read_current())
        self.lease.assert_called_once()
        self.assertEqual(4, len(self.statements))
        self.assertTrue(self.statements[2].startswith('SELECT'))

    def test_stale_expected_fails_without_update(self):
        with self.assertRaisesRegex(CleanerCutoverControlError, 'CURRENT_DRIFT'):
            self.port.advance(CleanerEpochTransition(0,1))
        self.assertEqual(1, self.port.read_current())
        self.assertFalse(any('UPDATE' in s for s in self.statements))

    def test_reuse_decrement_skip_and_forged_values_rejected_before_lease(self):
        for current, target in ((1,1),(1,0),(1,3),(-1,0),(True,2),(1,2.0),(1,'2')):
            with self.subTest(current=current,target=target):
                transition = object.__new__(CleanerEpochTransition)
                object.__setattr__(transition,'current_epoch',current)
                object.__setattr__(transition,'target_epoch',target)
                with self.assertRaises(CleanerCutoverControlError):
                    self.port.advance(transition)
        with self.assertRaisesRegex(CleanerCutoverControlError, 'TRANSITION_INVALID'):
            self.port.advance(SimpleNamespace(current_epoch=1,target_epoch=2))
        self.lease.assert_not_called()
        self.assertEqual([], self.statements)

    def test_hostile_integer_subclasses_rejected_in_both_fields_before_lease(self):
        class FormattingInt(int):
            def __format__(self, spec):
                return '3'

        class StringInt(int):
            def __str__(self):
                return '3'

        class ComparisonInt(int):
            def __eq__(self, other):
                return True

            def __ne__(self, other):
                return False

            def __lt__(self, other):
                return False

            def __add__(self, other):
                return 2

        for integer_type in (FormattingInt, StringInt, ComparisonInt):
            for field, value in (('current_epoch', 1), ('target_epoch', 2)):
                for forged in (False, True):
                    with self.subTest(integer_type=integer_type.__name__, field=field, forged=forged):
                        values = {'current_epoch': 1, 'target_epoch': 2}
                        values[field] = integer_type(value)
                        if forged:
                            transition = CleanerEpochTransition(1, 2)
                            object.__setattr__(transition, field, values[field])
                        else:
                            transition = CleanerEpochTransition(**values)
                        with self.assertRaisesRegex(CleanerCutoverControlError, 'CLEANER_EPOCH_VALUE_INVALID'):
                            self.port.advance(transition)
        self.lease.assert_not_called()
        self.assertEqual([], self.statements)
        self.assertEqual(1, self.port.read_current())

    def test_lease_failure_precedes_sql(self):
        self.lease.side_effect = RuntimeError('lease invalid')
        with self.assertRaisesRegex(RuntimeError,'lease invalid'):
            self.port.advance(CleanerEpochTransition(1,2))
        self.assertEqual([], self.statements)

    def test_concurrent_update_cas_affects_zero_rows(self):
        original = self._adapter
        def race(*args, **kwargs):
            self._sql('UPDATE propertyai.authority_epoch SET current_epoch=2')
            return original(*args,**kwargs)
        with patch('adcp.cleaner_cutover_control._run_psql',side_effect=race):
            with self.assertRaisesRegex(CleanerCutoverControlError,'CAS_NOT_APPLIED'):
                self.port.advance(CleanerEpochTransition(1,2))
        self.assertEqual(2,self.port.read_current())

    def test_factual_readback_detects_after_update_drift(self):
        original = self._adapter
        def drift(*args, **kwargs):
            result = original(*args,**kwargs)
            self._sql('UPDATE propertyai.authority_epoch SET current_epoch=3')
            return result
        with patch('adcp.cleaner_cutover_control._run_psql',side_effect=drift):
            with self.assertRaisesRegex(CleanerCutoverControlError,'CAS_READBACK_INVALID'):
                self.port.advance(CleanerEpochTransition(1,2))

    def test_cas_invalid_or_ambiguous_results_fail_closed(self):
        for output in ('', '{}\n{}', 'not json', '[]', '{"scope":"CLEANER_SCHEDULING","epoch":true}', '{"scope":"CLEANER_SCHEDULING","epoch":2.0}', '{"scope":"OTHER","epoch":2}'):
            with self.subTest(output=output), patch('adcp.cleaner_cutover_control._run_psql',return_value=SanitizedProcessResult(0,output,'')):
                with self.assertRaises(CleanerCutoverControlError):
                    self.port.advance(CleanerEpochTransition(1,2))
        with patch('adcp.cleaner_cutover_control._run_psql',return_value=SanitizedProcessResult(1,'','failed')):
            with self.assertRaisesRegex(CleanerCutoverControlError,'CAS_FAILED'):
                self.port.advance(CleanerEpochTransition(1,2))

    def test_boolean_cas_result_cannot_equal_integer_successor(self):
        self._sql('UPDATE propertyai.authority_epoch SET current_epoch=0')
        with patch('adcp.cleaner_cutover_control._run_psql',return_value=SanitizedProcessResult(0,'{"scope":"CLEANER_SCHEDULING","epoch":true}','')):
            with self.assertRaisesRegex(CleanerCutoverControlError,'CAS_READBACK_INVALID'):
                self.port.advance(CleanerEpochTransition(0,1))
        self.assertEqual(0,self.port.read_current())

    def test_read_mapping_invalid_epochs_rejected(self):
        for epoch in (-1,True,1.0,'1',None):
            with self.subTest(epoch=epoch), patch('adcp.cleaner_cutover_control._json_query',return_value={'scope':'CLEANER_SCHEDULING','epoch':epoch}):
                with self.assertRaisesRegex(CleanerCutoverControlError,'READBACK_INVALID'):
                    self.port.read_current()

    def test_shared_reader_rejects_ambiguous_rows(self):
        with patch('adcp.postgres_control._run_psql',return_value=SanitizedProcessResult(0,'{}\n{}','')):
            with self.assertRaisesRegex(TypedPostgresError,'CARDINALITY_INVALID'):
                self.port.read_current()

    def test_actual_frozen_sql_and_old_identifier_regression(self):
        self.assertEqual(2,self.port.advance(CleanerEpochTransition(1,2)))
        source = inspect.getsource(CanonicalCleanerEpochPort)
        self.assertNotIn('authority_scope_code',source)
        self.assertNotRegex(source,r'(?<!\.)\bauthority_epoch\b')
        for old_sql in (
            "SELECT authority_scope_code,authority_epoch FROM propertyai.authority_epoch",
            "UPDATE propertyai.authority_epoch SET authority_epoch=2 WHERE authority_scope_code='CLEANER_SCHEDULING'",
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                self._sql(old_sql)
        self.assertEqual(2,self.port.read_current())
