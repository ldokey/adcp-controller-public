from dataclasses import fields, replace
import copy
from contextlib import nullcontext
from datetime import datetime,timedelta,timezone
import hashlib
import json
import os
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from adcp import cleaner_worker_control as worker
from adcp import postgres_control as pg
from adcp import production_control as production
import test_postgres_control as existing
import test_postgres_approval_evidence as approval_tests


class WorkerControlTests(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.TypedPostgresControlTests("runTest")
        self.fixture.setUp()
        self.fixture._schema()
        self.addCleanup(self.fixture.tearDown)
        self.path = self.fixture.secret_dir / "worker.pgpass"
        self.policy = replace(self.fixture.policy, credentials={
            **self.fixture.policy.credentials,
            worker.WORKER_CREDENTIAL: pg._CredentialSpec(worker.WORKER_CREDENTIAL,
                self.path, pg._CredentialKind.PGPASS, worker.WORKER_LOGIN)})
        self.evidence = self.fixture.root / "worker-evidence"
        self.evidence.mkdir(mode=0o700)

    def create(self, operation_id="worker-credential-1",authority=None):
        return worker._create_worker_credential(self.fixture.store,
            request=worker.CleanerWorkerRequest(operation_id), change_id="TYPED-PG-TEST",
            authority=authority or self.fixture._authority(), policy=self.policy, control_decision_ref="DL98/WORKER",
            evidence_root=self.evidence, start_heartbeat=False)

    def provision(self, operation_id="worker-principal-1",authority=None):
        scope=(patch.object(pg,"resolve_production_operation_approval_evidence",
            return_value=SimpleNamespace(evidence_sha256="a"*64)) if authority is None else nullcontext())
        with scope:
            return worker._provision_worker(self.fixture.store,
                request=worker.CleanerWorkerRequest(operation_id), change_id="TYPED-PG-TEST",
                authority=authority or self.approval_authority(), policy=self.policy,
                control_decision_ref="DL98/WORKER", start_heartbeat=False)

    def write_credential(self, database=pg.CLEANER_DATABASE, role=worker.WORKER_LOGIN):
        self.path.write_text(f"127.0.0.1:5432:{database}:{role}:disposable-worker-secret\n")
        self.path.chmod(0o600)

    def approval_authority(self):
        commit,tree=pg.controller_git_identity(self.fixture.repo)
        binding=pg.ExpectedProductionOperationApprovalBinding(pg.PROJECT_CODE,"TYPED-PG-TEST","DL98",
            "CREATE_WORKER_PROTECTED_CREDENTIAL",("CREATE_EXACT_WORKER_PROTECTED_CREDENTIAL",),
            commit,tree,"create_cleaner_worker_protected_credential",{"role":worker.WORKER_LOGIN},None)
        return worker._WorkerAuthority(self.fixture.repo,commit,tree,"a"*64,binding,"DL98/WORKER")

    def test_authority_freshly_resolves_expiry_and_exact_evidence_each_guard(self):
        fixture=approval_tests.ProductionOperationApprovalEvidenceTests("runTest")
        fixture.setUp();self.addCleanup(fixture.tearDown)
        fixture.now=datetime.now(timezone.utc)
        payload=fixture.payload();fixture.write(payload)
        auth=worker._WorkerAuthority(self.fixture.repo,fixture.expected.controller_commit,
            fixture.expected.controller_tree,payload["evidence_sha256"],fixture.expected,fixture.ref)
        resolver=pg.resolve_production_operation_approval_evidence
        with patch.object(worker.GitSourceAuthority,"revalidate"), patch.object(pg,"_approval_evidence_source",return_value=fixture.source):
            auth.revalidate()
            with patch.object(pg,"resolve_production_operation_approval_evidence",
                side_effect=lambda *args,**kwargs:resolver(*args,**kwargs,now=fixture.now+timedelta(hours=2))):
                with self.assertRaisesRegex(pg.TypedPostgresError,"EXPIRED"):
                    auth.revalidate()
            fixture.write(fixture.payload(issued_at=(fixture.now-timedelta(minutes=4)).isoformat()))
            with self.assertRaisesRegex(pg.TypedPostgresError,"EVIDENCE_CHANGED"):
                auth.revalidate()

    def test_worker_dispatch_is_exact_and_unknown_subclass_rejected(self):
        auth=self.approval_authority()
        with patch.object(pg,"resolve_production_operation_approval_evidence",
            return_value=SimpleNamespace(evidence_sha256="a"*64)) as resolve:
            production._revalidate_authority(auth)
            resolve.assert_called_once()
        class Unapproved(worker._WorkerAuthority):pass
        bad=Unapproved(auth.root,auth.expected_head,auth.tree,auth.approval_evidence_sha256,
                       auth.approval_binding,auth.approval_reference)
        with self.assertRaisesRegex(production.ProductionControlError,"AUTHORITY_INVALID"):
            production._revalidate_authority(bad)

    def test_public_worker_password_retains_original_approval_binding(self):
        commit,tree=pg.controller_git_identity(self.fixture.repo)
        with patch.object(pg,"_controller_source_identity",return_value=(commit,tree,"apply_role_password_from_protected_file")),patch.object(
            pg,"_resolve_public_operation_approval",return_value=SimpleNamespace(evidence_sha256="a"*64)),patch.object(
            pg,"_canonical_typed_postgres_control_store",return_value=nullcontext(self.fixture.store)),patch.object(
            pg,"_apply_role_password_from_protected_file",return_value="NO_EFFECT") as apply:
            value=pg.apply_role_password_from_protected_file(change_id="TYPED-PG-TEST",
                request=pg.ApplyRolePasswordFromProtectedFileRequest(pg.PasswordCredentialOperation.CLEANER_WORKER,"worker-password"),
                control_decision_ref="DL98/WORKER",gate_or_control_id="DL98")
        self.assertEqual("NO_EFFECT",value)
        authority=apply.call_args.kwargs["authority"]
        self.assertIs(type(authority),worker._WorkerAuthority)
        self.assertEqual("worker-password",authority.approval_binding.target_identity["operation_id"])
        self.assertEqual("APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE",authority.approval_binding.operation_kind)
        self.assertEqual("a"*64,authority.approval_evidence_sha256)

    def test_principal_jit_expiry_after_prepared_blocks_sql_and_final(self):
        auth=self.approval_authority();live=[True]
        def resolve(*args,**kwargs):
            if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
            return SimpleNamespace(evidence_sha256="a"*64)
        original=pg._append_receipt
        def append(*args,**kwargs):
            result=original(*args,**kwargs)
            if kwargs["phase"]=="PREPARED":live[0]=False
            return result
        before={**worker._worker_expected_state(),"principal":None,"memberships":[]}
        with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
            pg,"_append_receipt",side_effect=append),patch.object(worker,"_worker_artifact",return_value=b"fixture"),patch.object(
            worker,"_worker_state",return_value=before),patch.object(pg,"_run_psql") as sql:
            with self.assertRaisesRegex(pg.TypedPostgresError,"APPROVAL_EXPIRED"):
                self.provision(authority=auth)
            sql.assert_not_called()

    def test_file_jit_expiry_after_prepared_blocks_creation(self):
        auth=self.approval_authority();live=[True]
        def resolve(*args,**kwargs):
            if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
            return SimpleNamespace(evidence_sha256="a"*64)
        original=worker._exclusive_json
        def append(path,value):
            original(path,value)
            if value["phase"]=="PREPARED":live[0]=False
        with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
            worker,"_exclusive_json",side_effect=append),patch.object(worker,"_worker_state",return_value=worker._worker_expected_state()):
            with self.assertRaisesRegex(pg.TypedPostgresError,"APPROVAL_EXPIRED"):
                self.create(authority=auth)
        self.assertFalse(self.path.exists())
        self.assertEqual(1,len(list(self.evidence.iterdir())))

    def test_password_jit_expiry_after_prepared_blocks_password_effect(self):
        self.write_credential();auth=self.approval_authority();live=[True]
        def resolve(*args,**kwargs):
            if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
            return SimpleNamespace(evidence_sha256="a"*64)
        original=pg._append_receipt
        def append(*args,**kwargs):
            result=original(*args,**kwargs)
            if kwargs["phase"]=="PREPARED":live[0]=False
            return result
        request=pg._ApplyRolePasswordFromProtectedFileIntent(pg.ApprovedPostgresRole.CLEANER_WORKER,
            worker.WORKER_CREDENTIAL,os.getuid(),0o600,"worker-password")
        with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
            pg,"_append_receipt",side_effect=append),patch.object(worker,"_worker_state",return_value=worker._worker_expected_state()),patch.object(
            pg,"_query_postgres_catalog",return_value={"exists":True,"role":worker.WORKER_LOGIN}),patch.object(pg,"_run_psql") as sql:
            with self.assertRaisesRegex(pg.TypedPostgresError,"APPROVAL_EXPIRED"):
                pg._apply_role_password_from_protected_file(self.fixture.store,change_id="TYPED-PG-TEST",authority=auth,
                    policy=self.policy,request=request,control_decision_ref="DL98/WORKER",start_heartbeat=False)
            sql.assert_not_called()

    def test_changed_jit_after_file_effect_prevents_final_and_readonly_facts_remain(self):
        auth=self.approval_authority();changed=[False]
        original=worker._exclusive_json
        def append(path,value):
            original(path,value)
            if value["phase"]=="EFFECT":changed[0]=True
        with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=lambda *a,**k:
            SimpleNamespace(evidence_sha256=("b" if changed[0] else "a")*64)),patch.object(
            worker,"_exclusive_json",side_effect=append),patch.object(worker,"_worker_state",return_value=worker._worker_expected_state()):
            with self.assertRaises(Exception):self.create(authority=auth)
        self.assertTrue(self.path.exists())
        with patch.object(pg,"_canonical_cleaner_postgres_policy",return_value=self.policy),patch.object(
            pg,"_validate_sealed_canonical_policy"),patch.object(worker,"WORKER_EVIDENCE_ROOT",self.evidence),patch.object(
            pg,"resolve_production_operation_approval_evidence",side_effect=AssertionError("read-only must not require live JIT")):
            value=worker.read_cleaner_worker_credential_reconciliation(change_id="TYPED-PG-TEST",
                request=worker.CleanerWorkerRequest("worker-credential-1"))
        self.assertEqual("EFFECT_APPLIED_FINAL_MISSING",value["status"])

    def test_receipt_only_reconciliation_expiry_preserves_pending_final(self):
        auth=self.approval_authority();live=[True]
        def resolve(*args,**kwargs):
            if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
            return SimpleNamespace(evidence_sha256="a"*64)
        original_write=worker._exclusive_json
        def fail_final(path,value):
            if value["phase"]=="FINAL":raise OSError("fixture final failure")
            return original_write(path,value)
        with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
            worker,"_worker_state",return_value=worker._worker_expected_state()),patch.object(worker,"_exclusive_json",side_effect=fail_final):
            with self.assertRaises(Exception):self.create(authority=auth)
        original_read=worker._read_credential_reconciliation;reads=[0]
        def read(*args,**kwargs):
            value=original_read(*args,**kwargs);reads[0]+=1
            if reads[0]==2:live[0]=False
            return value
        with patch.object(worker,"_worker_approval",return_value=auth),patch.object(
            pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
            worker,"_read_credential_reconciliation",side_effect=read),patch.object(
            pg,"_canonical_cleaner_postgres_policy",return_value=self.policy),patch.object(pg,"_validate_sealed_canonical_policy"),patch.object(
            worker,"WORKER_EVIDENCE_ROOT",self.evidence),patch.object(
            pg,"_canonical_typed_postgres_control_store",return_value=nullcontext(self.fixture.store)):
            with self.assertRaises(Exception):
                worker.reconcile_cleaner_worker_protected_credential(change_id="TYPED-PG-TEST",
                    request=worker.CleanerWorkerRequest("worker-credential-1"),control_decision_ref="DL98/WORKER",gate_or_control_id="DL98")
        self.assertEqual(0,len(list(self.evidence.glob("*.final.json"))))
        self.assertTrue(self.path.exists())
        self.assertGreaterEqual(reads[0],2)
        self.assertFalse(live[0])

    def test_real_pg_composition_guards_after_canonical_read_for_both_worker_mutations(self):
        self.write_credential()
        after=worker._worker_expected_state();before={**after,"principal":None,"memberships":[]}
        artifact=(Path(__file__).resolve().parents[1]/worker.WORKER_SQL_PATH).read_bytes()
        for kind in ("principal","password"):
            for mode in ("valid","expired","substituted","lease_lost","expired_after_fingerprint"):
                with self.subTest(kind=kind,mode=mode):
                    operation=f"dispatch-{kind}-{mode}";live=[True];hash_value=["a"*64]
                    dispatched=[];canonical_reads=[];canonical_done=[False]
                    auth=self.approval_authority()
                    def resolve(*args,**kwargs):
                        if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
                        return SimpleNamespace(evidence_sha256=hash_value[0])
                    def canonical(*args,**kwargs):
                        canonical_reads.append(True);canonical_done[0]=True
                        if mode=="expired":live[0]=False
                        elif mode=="substituted":hash_value[0]="b"*64
                        elif mode=="lease_lost":
                            row=self.fixture.store.get_global_production_writer_lease()
                            self.fixture.store.release_global_production_writer(
                                operation_key=hashlib.sha256(operation.encode()).hexdigest(),
                                owner_id=row["owner_id"],fencing_token=row["fencing_token"])
                    actual_run=pg.subprocess.run
                    def run(argv,*args,**kwargs):
                        if str(argv[0])==str(self.policy.psql_path):
                            dispatched.append(live[0])
                            return SimpleNamespace(returncode=0,stdout=b"",stderr=b"")
                        return actual_run(argv,*args,**kwargs)
                    actual_fingerprint=pg._revalidate_path_fingerprint
                    def fingerprint(*args,**kwargs):
                        actual_fingerprint(*args,**kwargs)
                        if canonical_done[0] and mode=="expired_after_fingerprint":live[0]=False
                    def call():
                        if kind=="principal":return self.provision(operation,authority=auth)
                        request=pg._ApplyRolePasswordFromProtectedFileIntent(pg.ApprovedPostgresRole.CLEANER_WORKER,
                            worker.WORKER_CREDENTIAL,os.getuid(),0o600,operation)
                        return pg._apply_role_password_from_protected_file(self.fixture.store,
                            change_id="TYPED-PG-TEST",authority=auth,policy=self.policy,request=request,
                            control_decision_ref="DL98/WORKER",start_heartbeat=False)
                    with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
                        pg,"_validate_canonical_postgres_authority",side_effect=canonical),patch.object(pg.subprocess,"run",side_effect=run),patch.object(
                        pg,"_revalidate_path_fingerprint",side_effect=fingerprint),patch.object(worker,"_worker_artifact",return_value=artifact),patch.object(
                        worker,"_worker_state",side_effect=lambda _policy:before if kind=="principal" and not dispatched else after),patch.object(
                        pg,"_query_postgres_catalog",return_value={"exists":True,"role":worker.WORKER_LOGIN}),patch.object(
                        worker,"_worker_login_proof",return_value=dict(exists=True,role=worker.WORKER_LOGIN,
                            session_user=worker.WORKER_LOGIN,current_user=worker.WORKER_CAPABILITY,database=pg.CLEANER_DATABASE)):
                        if mode=="valid":self.assertEqual("FINAL",call().receipt_phase)
                        else:
                            with self.assertRaises(Exception):call()
                    self.assertEqual(1,len(canonical_reads))
                    self.assertEqual([True] if mode=="valid" else [],dispatched)
                    self.assertIsNone(worker._ACTIVE_WORKER_PG_MUTATION.get())

    def test_file_guards_follow_blocking_catalog_read_and_secret_generation(self):
        for mode in ("catalog_read","entropy"):
            with self.subTest(mode=mode):
                auth=self.approval_authority();live=[True]
                def resolve(*args,**kwargs):
                    if not live[0]:raise pg.PostgresApprovalEvidenceError("APPROVAL_EXPIRED")
                    return SimpleNamespace(evidence_sha256="a"*64)
                def state(*args):
                    if mode=="catalog_read":live[0]=False
                    return worker._worker_expected_state()
                def entropy(*args):
                    live[0]=False
                    return "a"*64
                with patch.object(pg,"resolve_production_operation_approval_evidence",side_effect=resolve),patch.object(
                    worker,"_worker_state",side_effect=state),patch.object(worker.secrets,"token_hex",side_effect=entropy):
                    with self.assertRaises(Exception):self.create("file-delay-"+mode,authority=auth)
                self.assertFalse(self.path.exists())
                self.assertFalse(live[0])
                self.assertEqual(0 if mode=="catalog_read" else 1,len(list(self.evidence.glob("*.prepared.json"))))

    def test_fixed_contract_and_no_generic_public_inputs(self):
        self.assertEqual(["operation_id"], [f.name for f in fields(worker.CleanerWorkerRequest)])
        policy = pg._canonical_cleaner_postgres_policy()
        pg._validate_sealed_canonical_policy(policy)
        self.assertEqual(pg.CANONICAL_SECRET_DIR / "worker.pgpass", policy.credentials[worker.WORKER_CREDENTIAL].path)
        with self.assertRaises(TypeError):
            worker.provision_cleaner_worker_principal(change_id="x", request=worker.CleanerWorkerRequest("y"),
                control_decision_ref="z", gate_or_control_id="DL98", role="propertyai_cleaner_app")

    def test_public_approval_failure_precedes_store_file_and_pg(self):
        for function in (worker.provision_cleaner_worker_principal, worker.create_cleaner_worker_protected_credential):
            with self.subTest(function=function.__name__), patch.object(pg, "_resolve_public_operation_approval",
                side_effect=pg.TypedPostgresError("APPROVAL_REQUIRED")) as approval, patch.object(
                pg, "_canonical_typed_postgres_control_store") as store:
                with self.assertRaisesRegex(pg.TypedPostgresError, "APPROVAL_REQUIRED"):
                    function(change_id="TYPED-PG-TEST", request=worker.CleanerWorkerRequest("worker-1"),
                             control_decision_ref="DL98/WORKER", gate_or_control_id="DL98")
                store.assert_not_called()
                self.assertEqual("worker-1", approval.call_args.kwargs["target_identity"]["operation_id"])
                self.assertEqual(worker.WORKER_LOGIN, approval.call_args.kwargs["target_identity"]["role"])

    def test_principal_full_state_rejects_role_membership_and_connect_drift(self):
        exact = worker._worker_expected_state()
        self.assertEqual("NOOP_EXACT", worker._validate_worker_state(exact, final=True))
        for section in ("principal", "capability"):
            for key, value in exact[section].items():
                bad = copy.deepcopy(exact)
                bad[section][key] = not value if isinstance(value, bool) else "wrong"
                with self.subTest(section=section,key=key), self.assertRaises(pg.TypedPostgresError):
                    worker._validate_worker_state(bad)
        for bad in ({**exact,"public_connect":False}, {**exact,"memberships":exact["memberships"] * 2},
                    {**exact,"memberships":[{**exact["memberships"][0],"granted_role":"propertyai_app_runtime"}]}):
            with self.assertRaises(pg.TypedPostgresError):
                worker._validate_worker_state(bad)

    def test_principal_receipts_and_exact_replay_no_second_effect(self):
        after = worker._worker_expected_state()
        before = {**after, "principal":None, "memberships":[]}
        with patch.object(worker,"_worker_artifact",return_value=b"fixed fixture"), patch.object(
            worker,"_worker_state",side_effect=[before,after]), patch.object(pg,"_run_psql",
            return_value=pg.SanitizedProcessResult(0,"","")) as run:
            receipt = self.provision()
        self.assertEqual("FINAL",receipt.receipt_phase)
        self.assertEqual("EXECUTE_AUTHORIZED_SQL_FILE",receipt.operation_type)
        self.assertEqual(worker.WORKER_SQL_SHA256,receipt.artifact_sha256)
        self.assertEqual(worker.WORKER_LOGIN,receipt.principal_identity)
        run.assert_called_once()
        with patch.object(worker,"_worker_state",return_value=after), patch.object(pg,"_run_psql") as run:
            self.assertEqual(receipt,self.provision())
            run.assert_not_called()

    def test_unknown_artifact_does_not_route_to_bootstrap_or_worker(self):
        for path, digest in (("unapproved.sql",worker.WORKER_SQL_SHA256),(worker.WORKER_SQL_PATH,"0"*64)):
            result = pg._TypedEffectResult(pg.TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE,
                "APPLIED",{},None,path,digest)
            with self.assertRaises(pg.TypedPostgresError):
                pg._validate_effect_postcondition(result,worker._worker_expected_state())

    def test_generation_is_exclusive_protected_secret_free_and_w08_released(self):
        with patch.object(worker,"_worker_state",return_value=worker._worker_expected_state()):
            result = self.create()
        self.assertTrue(self.path.is_file())
        self.assertEqual(0o600,self.path.stat().st_mode & 0o777)
        secret = pg._password_from_credential(self.policy, pg._validate_credential(
            self.policy,worker.WORKER_CREDENTIAL,reveal_text=True))
        evidence = "".join(path.read_text() for path in self.evidence.iterdir())
        self.assertNotIn(secret,evidence)
        self.assertNotIn(hashlib.sha256(secret.encode()).hexdigest(),evidence)
        self.assertNotIn(secret,repr(result))
        self.assertEqual(3,len(list(self.evidence.iterdir())))
        original=self.path.read_bytes()
        with self.assertRaisesRegex(pg.TypedPostgresError,"RECONCILIATION_REQUIRED"):
            self.create()
        self.assertEqual(original,self.path.read_bytes())

    def test_reconciliation_distinguishes_interruption_phases_without_mutation(self):
        request=worker.CleanerWorkerRequest("worker-reconcile")
        identity=worker._credential_evidence_identity(request,"TYPED-PG-TEST","DL98/WORKER",self.fixture._authority())
        prepared,effect,final=worker._credential_paths(self.evidence,identity)
        def status():
            return worker._read_credential_reconciliation(self.policy,self.evidence,identity)["status"]
        self.assertEqual("PRISTINE",status())
        worker._exclusive_json(prepared,{**identity,"phase":"PREPARED"})
        self.assertEqual("PREPARED_FILE_ABSENT_RECONCILIATION_REQUIRED",status())
        self.write_credential()
        self.assertEqual("VALID_FILE_WITHOUT_DURABLE_EFFECT_IDENTITY_RECONCILIATION_REQUIRED",status())
        metadata=worker._credential_metadata(self.policy)
        worker._exclusive_json(effect,{**identity,"phase":"EFFECT","metadata":metadata})
        self.assertEqual("EFFECT_APPLIED_FINAL_MISSING",status())
        worker._exclusive_json(final,{**identity,"phase":"FINAL","metadata":metadata})
        self.assertEqual("FINAL_PASS",status())
        with self.assertRaisesRegex(pg.TypedPostgresError,"IDENTITY_DRIFT"):
            worker._read_credential_reconciliation(self.policy,self.evidence,{**identity,"controller_tree":"different"})
        self.assertEqual(0,self.fixture.store.connection.execute(
            "SELECT count(*) FROM global_production_writer_lease WHERE owner_id IS NOT NULL").fetchone()[0])

    def test_final_failure_preserves_file_and_prepared_never_regenerates(self):
        real = worker._exclusive_json
        def fail_final(path,value):
            if value["phase"] == "FINAL":
                raise OSError("fixture final failure")
            return real(path,value)
        with patch.object(worker,"_worker_state",return_value=worker._worker_expected_state()), patch.object(
            worker,"_exclusive_json",side_effect=fail_final):
            with self.assertRaises(Exception):
                self.create()
        original=self.path.read_bytes()
        with self.assertRaisesRegex(pg.TypedPostgresError,"RECONCILIATION_REQUIRED"):
            self.create()
        self.assertEqual(original,self.path.read_bytes())
        with patch.object(worker,"_worker_approval",return_value=self.fixture._authority()), patch.object(
            pg,"_canonical_cleaner_postgres_policy",return_value=self.policy), patch.object(
            pg,"_validate_sealed_canonical_policy"), patch.object(worker,"WORKER_EVIDENCE_ROOT",self.evidence), patch.object(
            pg,"_canonical_typed_postgres_control_store",return_value=nullcontext(self.fixture.store)):
            result=worker.reconcile_cleaner_worker_protected_credential(change_id="TYPED-PG-TEST",
                request=worker.CleanerWorkerRequest("worker-credential-1"),control_decision_ref="DL98/WORKER",gate_or_control_id="DL98")
        self.assertEqual("FINAL_PASS",result["status"])
        self.assertEqual(original,self.path.read_bytes())

    def test_wrong_metadata_or_binding_rejected(self):
        for database,role in (("*",worker.WORKER_LOGIN),(pg.CLEANER_DATABASE,pg.CLEANER_APP_LOGIN_ROLE)):
            self.write_credential(database,role)
            with self.assertRaises(pg.TypedPostgresError):
                worker._credential_metadata(self.policy)
        self.write_credential()
        self.path.chmod(0o644)
        with self.assertRaises(pg.TypedPostgresError):
            worker._credential_metadata(self.policy)
        self.path.unlink()
        self.path.symlink_to(self.fixture.app_pgpass)
        with self.assertRaises(pg.TypedPostgresError):
            worker._credential_metadata(self.policy)

    def test_worker_login_proof_requires_actual_identity_and_clean_environment(self):
        self.write_credential()
        exact=dict(exists=True,role=worker.WORKER_LOGIN,session_user=worker.WORKER_LOGIN,
                   current_user=worker.WORKER_CAPABILITY,database=pg.CLEANER_DATABASE)
        for proof in (exact,{**exact,"session_user":pg.CLEANER_APP_LOGIN_ROLE},
                      {**exact,"current_user":worker.WORKER_LOGIN},{**exact,"database":"postgres"}):
            with patch.dict(os.environ,{},clear=True), patch.object(worker,"_worker_state",
                return_value=worker._worker_expected_state()), patch.object(pg,"_spawn_psql",
                return_value=pg.SanitizedProcessResult(0,json.dumps(proof),"")) as spawn:
                if proof == exact:
                    self.assertEqual(exact,worker._worker_login_proof(self.policy))
                else:
                    with self.assertRaises(pg.TypedPostgresError):
                        worker._worker_login_proof(self.policy)
                self.assertIn(b"SET ROLE propertyai_async_worker",spawn.call_args.kwargs["stdin_sql"])
        with patch.dict(os.environ,{"PGPASSWORD":"wrong"},clear=True), patch.object(worker,"_worker_state",
            return_value=worker._worker_expected_state()), patch.object(pg,"_spawn_psql") as spawn:
            with self.assertRaisesRegex(pg.TypedPostgresError,"AMBIENT"):
                worker._worker_login_proof(self.policy)
            spawn.assert_not_called()

    def test_password_requires_worker_proof_and_does_not_accept_app_credential(self):
        request=pg._ApplyRolePasswordFromProtectedFileIntent(pg.ApprovedPostgresRole.CLEANER_WORKER,
            pg.CredentialReference.APP_PGPASS,os.getuid(),0o600,"worker-password")
        with self.assertRaisesRegex(pg.TypedPostgresError,"BINDING_MISMATCH"):
            pg._apply_role_password_from_protected_file(self.fixture.store, change_id="TYPED-PG-TEST",
                authority=self.fixture._authority(),policy=self.policy,request=request,start_heartbeat=False)
        result=pg._TypedEffectResult(pg.TypedOperationType.APPLY_ROLE_PASSWORD_FROM_PROTECTED_FILE,"APPLIED",{},None)
        with self.assertRaises(pg.TypedPostgresError):
            pg._validate_effect_postcondition(result,{"exists":True,"role":worker.WORKER_LOGIN})

    def test_worker_password_receipt_requires_authentication_and_replay_is_no_effect(self):
        self.write_credential()
        request=pg._ApplyRolePasswordFromProtectedFileIntent(pg.ApprovedPostgresRole.CLEANER_WORKER,
            worker.WORKER_CREDENTIAL,os.getuid(),0o600,"worker-password")
        proof=dict(exists=True,role=worker.WORKER_LOGIN,session_user=worker.WORKER_LOGIN,
                   current_user=worker.WORKER_CAPABILITY,database=pg.CLEANER_DATABASE)
        def apply():
            return pg._apply_role_password_from_protected_file(self.fixture.store,change_id="TYPED-PG-TEST",
                authority=self.approval_authority(),policy=self.policy,request=request,
                control_decision_ref="DL98/WORKER",start_heartbeat=False)
        with patch.object(pg,"resolve_production_operation_approval_evidence",return_value=SimpleNamespace(evidence_sha256="a"*64)),patch.object(pg,"_query_postgres_catalog",return_value={"exists":True,"role":worker.WORKER_LOGIN}), patch.object(
            worker,"_worker_state",return_value=worker._worker_expected_state()), patch.object(worker,"_worker_login_proof",
            return_value=proof), patch.object(pg,"_run_psql",return_value=pg.SanitizedProcessResult(0,"","")) as run:
            receipt=apply()
            self.assertEqual("FINAL",receipt.receipt_phase)
            self.assertEqual(worker.WORKER_CREDENTIAL.value,receipt.credential_reference)
            self.assertEqual(receipt,apply())
            run.assert_called_once()
            self.assertNotIn("disposable-worker-secret",repr(receipt))

    def test_worker_spawn_forces_scram_and_excludes_secret_argv(self):
        self.write_credential()
        material=pg._validate_credential(self.policy,worker.WORKER_CREDENTIAL,reveal_text=True)
        with patch.object(pg.subprocess,"run",return_value=type("Result",(),{
            "returncode":0,"stdout":b"","stderr":b""})()) as run:
            pg._spawn_psql(self.policy,database=pg.CLEANER_DATABASE,execution_role=worker.WORKER_LOGIN,
                stdin_sql=b"SELECT 1",credential=material,connection_secret="disposable-worker-secret",read_only=True)
        self.assertEqual("scram-sha-256",run.call_args.kwargs["env"]["PGREQUIREAUTH"])
        self.assertNotIn("disposable-worker-secret",repr(run.call_args.args))
        self.assertNotIn("PGPASSWORD",run.call_args.kwargs["env"])


class WorkerDisposableSqlTests(existing.CleanerPrincipalDisposablePostgresTests):
    # Reuse only disposable cluster plumbing; the production source SQL is the fixture.
    def test_worker_source_artifact_create_noop_and_conflict_atomicity(self):
        path=Path(__file__).resolve().parents[1]/worker.WORKER_SQL_PATH
        raw=path.read_bytes()
        self.assertEqual(worker.WORKER_SQL_SHA256,hashlib.sha256(raw).hexdigest())
        sql=raw.decode()
        setup="CREATE ROLE propertyai_async_worker NOLOGIN NOINHERIT;"
        result=self.psql("BEGIN;"+setup+sql+sql+"SELECT rolcanlogin FROM pg_roles WHERE rolname='propertyai_cleaner_worker';ROLLBACK;")
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual("t",result.stdout.strip())
        cases=("CREATE ROLE propertyai_cleaner_worker LOGIN INHERIT;",
               "CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT; CREATE ROLE wrong; GRANT wrong TO propertyai_cleaner_worker;",
               "CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT; GRANT CONNECT ON DATABASE propertyai_cleaner_prod TO propertyai_cleaner_worker;",
               "CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT; CREATE TABLE worker_test(i int); GRANT UPDATE(i) ON worker_test TO propertyai_cleaner_worker;",
               "CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT; CREATE FUNCTION worker_test() RETURNS int LANGUAGE SQL AS 'SELECT 1'; GRANT EXECUTE ON FUNCTION worker_test() TO propertyai_cleaner_worker;",
               "CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT; CREATE TABLE worker_owned(i int); ALTER TABLE worker_owned OWNER TO propertyai_cleaner_worker;",
               "REVOKE CONNECT ON DATABASE propertyai_cleaner_prod FROM PUBLIC;")
        for conflict in cases:
            with self.subTest(conflict=conflict):
                result=self.psql("BEGIN;"+setup+conflict+sql+"ROLLBACK;")
                self.assertNotEqual(0,result.returncode)
        count=self.psql("SELECT count(*) FROM pg_roles WHERE rolname='propertyai_cleaner_worker';",check=True)
        self.assertEqual("0",count.stdout.strip())

    def test_real_worker_membership_isolated_both_directions(self):
        sql=(Path(__file__).resolve().parents[1]/worker.WORKER_SQL_PATH).read_text()
        result=self.psql("BEGIN;CREATE ROLE propertyai_async_worker NOLOGIN NOINHERIT;"
            "CREATE ROLE propertyai_app_runtime NOLOGIN NOINHERIT;"
            "CREATE ROLE propertyai_cleaner_app LOGIN NOINHERIT;"
            "GRANT propertyai_app_runtime TO propertyai_cleaner_app WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;"
            +sql+"SELECT pg_has_role('propertyai_cleaner_app','propertyai_async_worker','SET'),"
            "pg_has_role('propertyai_cleaner_worker','propertyai_app_runtime','SET'),"
            "pg_has_role('propertyai_cleaner_worker','propertyai_async_worker','SET');ROLLBACK;")
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual("f|f|t",result.stdout.strip())
