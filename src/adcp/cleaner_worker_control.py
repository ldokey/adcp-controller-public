"""DL98's one worker identity. Public requests carry no SQL, role, or path."""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any, Mapping

from adcp import postgres_control as pg
from adcp.production_control import DeploymentStep, GitSourceAuthority, run_controlled_deployment
from adcp.store.migrations import validate_schema

WORKER_SQL_PATH = "src/adcp/sql/provision_cleaner_worker.sql"
WORKER_SQL_SHA256 = "b94854ee1710affc582fe6d450ce1c5b57766879c4c24cb6c24ffdf346afb00c"
WORKER_LOGIN = pg.CLEANER_WORKER_LOGIN_ROLE
WORKER_CAPABILITY = "propertyai_async_worker"
WORKER_CREDENTIAL = pg.CredentialReference.WORKER_PGPASS
WORKER_EVIDENCE_ROOT = Path("/Users/kate/DKATE/adcp-runtime/evidence/worker-credential")


@dataclass(frozen=True)
class CleanerWorkerRequest:
    operation_id: str


@dataclass(frozen=True)
class _WorkerAuthority:
    root: Path
    expected_head: str
    tree: str
    approval_evidence_sha256: str
    approval_binding: pg.ExpectedProductionOperationApprovalBinding
    approval_reference: str

    def revalidate(self):
        GitSourceAuthority(self.root, self.expected_head, require_clean=True).revalidate()
        try:
            observed=pg.resolve_production_operation_approval_evidence(
                pg._approval_evidence_source(), control_decision_ref=self.approval_reference,
                expected=self.approval_binding)
        except pg.PostgresApprovalEvidenceError as error:
            raise pg.TypedPostgresError(error.code,error.detail) from None
        if observed.evidence_sha256 != self.approval_evidence_sha256:
            raise pg.TypedPostgresError("WORKER_APPROVAL_EVIDENCE_CHANGED")


_ACTIVE_WORKER_PG_MUTATION: ContextVar[tuple[Any,_WorkerAuthority,str,str] | None] = ContextVar(
    "dl98_exact_worker_pg_mutation", default=None)


@contextmanager
def _worker_pg_mutation(store,authority,change_id,operation_id):
    """Bind only the two source-sealed worker PG effects to their current W08."""
    if type(authority) is not _WorkerAuthority:
        raise pg.TypedPostgresError("WORKER_PG_MUTATION_AUTHORITY_INVALID")
    if _ACTIVE_WORKER_PG_MUTATION.get() is not None:
        raise pg.TypedPostgresError("WORKER_PG_MUTATION_NESTING_FORBIDDEN")
    token=_ACTIVE_WORKER_PG_MUTATION.set((store,authority,change_id,operation_id))
    try:
        _revalidate_worker_pg_dispatch()
        yield
    finally:
        _ACTIVE_WORKER_PG_MUTATION.reset(token)


def _revalidate_worker_pg_dispatch():
    binding=_ACTIVE_WORKER_PG_MUTATION.get()
    if binding is not None:
        store,authority,change_id,operation_id=binding
        pg._assert_current_typed_authority(store,authority,change_id=change_id,deployment_id=operation_id)


def _worker_expected_state() -> dict[str, Any]:
    def role(name: str, login: bool) -> dict[str, Any]:
        return dict(role=name, can_login=login, inherit=False, superuser=False,
                    create_db=False, create_role=False, replication=False,
                    bypass_rls=False, connection_limit=-1)
    return dict(database=pg.CLEANER_DATABASE, public_connect=True, direct_privileges=False,
                principal=role(WORKER_LOGIN, True), capability=role(WORKER_CAPABILITY, False),
                memberships=[dict(granted_role=WORKER_CAPABILITY, member_role=WORKER_LOGIN,
                                  inherit=False, set=True, admin=False)])


def _worker_state(policy) -> Mapping[str, Any]:
    def role(name: str) -> str:
        return ("(SELECT jsonb_build_object('role',rolname,'can_login',rolcanlogin,"
                "'inherit',rolinherit,'superuser',rolsuper,'create_db',rolcreatedb,"
                "'create_role',rolcreaterole,'replication',rolreplication,'bypass_rls',rolbypassrls,"
                "'connection_limit',rolconnlimit) FROM pg_catalog.pg_roles WHERE rolname="
                + pg._sql_literal(name) + ")")
    sql = ("SELECT jsonb_build_object('database',current_database(),'principal'," + role(WORKER_LOGIN)
           + ",'capability'," + role(WORKER_CAPABILITY)
           + ",'public_connect',EXISTS(SELECT FROM pg_catalog.pg_database d,"
           "LATERAL aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a "
           "WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type='CONNECT'),"
           "'direct_privileges',EXISTS(SELECT FROM ("
           "SELECT datdba AS owner,datacl AS acl FROM pg_catalog.pg_database "
           "UNION ALL SELECT nspowner,nspacl FROM pg_catalog.pg_namespace "
           "UNION ALL SELECT relowner,relacl FROM pg_catalog.pg_class "
           "UNION ALL SELECT 0::oid,attacl FROM pg_catalog.pg_attribute "
           "UNION ALL SELECT proowner,proacl FROM pg_catalog.pg_proc) objects "
           "LEFT JOIN LATERAL aclexplode(objects.acl) a ON true "
           "WHERE objects.owner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker') "
           "OR a.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker')),"
           "'memberships',COALESCE((SELECT jsonb_agg(jsonb_build_object('granted_role',g.rolname,"
           "'member_role',u.rolname,'inherit',m.inherit_option,'set',m.set_option,'admin',m.admin_option) "
           "ORDER BY g.rolname,u.rolname,m.grantor) FROM pg_catalog.pg_auth_members m "
           "JOIN pg_catalog.pg_roles g ON g.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member "
           "WHERE g.rolname IN ('propertyai_cleaner_worker','propertyai_async_worker') "
           "OR u.rolname IN ('propertyai_cleaner_worker','propertyai_async_worker')),'[]'::jsonb))")
    return pg._json_query(policy, database=pg.CLEANER_DATABASE, sql=sql)


def _validate_worker_state(state: Mapping[str, Any], *, final: bool = False) -> str:
    exact = _worker_expected_state()
    if pg._state_fingerprint(state) == pg._state_fingerprint(exact):
        return "NOOP_EXACT"
    if not final:
        for principal in (None, exact["principal"]):
            allowed = {**exact, "principal": principal, "memberships": []}
            if pg._state_fingerprint(state) == pg._state_fingerprint(allowed):
                return "CREATE_EXACT" if principal is None else "COMPLETE_MEMBERSHIP"
    raise pg.TypedPostgresError("POSTGRES_WORKER_PRINCIPAL_DRIFT")


def _worker_artifact() -> bytes:
    path = pg.CANONICAL_CONTROLLER_SOURCE_ROOT / WORKER_SQL_PATH
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise pg.TypedPostgresError("WORKER_SQL_ARTIFACT_SYMLINK_FORBIDDEN")
    raw, _ = pg._read_pinned_file(path, code_prefix="WORKER_SQL_ARTIFACT")
    if hashlib.sha256(raw).hexdigest() != WORKER_SQL_SHA256:
        raise pg.TypedPostgresError("WORKER_SQL_ARTIFACT_HASH_MISMATCH")
    return raw


def _worker_approval(request, change_id, control_decision_ref, gate_or_control_id,
                     *, entrypoint, kind, scopes, artifact=None):
    if type(request) is not CleanerWorkerRequest:
        raise pg.TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    if any(key.startswith("PG") for key in os.environ):
        raise pg.TypedPostgresError("POSTGRES_WORKER_AMBIENT_CREDENTIAL_FORBIDDEN")
    pg._validate_control_identifiers(change_id, control_decision_ref, request.operation_id)
    commit, tree, _entry = pg._controller_source_identity(entrypoint)
    target={"database": pg.CLEANER_DATABASE, "role": WORKER_LOGIN,
            "capability_role": WORKER_CAPABILITY,
            "credential_reference": WORKER_CREDENTIAL.value,
            "operation_id": request.operation_id}
    approval = pg._resolve_public_operation_approval(
        change_id=change_id, control_decision_ref=control_decision_ref,
        gate_or_control_id=gate_or_control_id, operation_kind=kind,
        authorized_effect_scope=scopes, entrypoint=entrypoint,
        target_identity=target,
        operation_artifact_identity=artifact)
    if pg._controller_source_identity(entrypoint)[:2] != (commit, tree):
        raise pg.TypedPostgresError("WORKER_APPROVAL_SOURCE_CHANGED")
    binding=pg.ExpectedProductionOperationApprovalBinding(
        project_code=pg.PROJECT_CODE,change_id=change_id,gate_or_control_id=gate_or_control_id,
        operation_kind=kind,authorized_effect_scope=scopes,controller_commit=commit,
        controller_tree=tree,controller_entrypoint=entrypoint,target_identity=target,
        operation_artifact_identity=artifact)
    return _WorkerAuthority(pg.CANONICAL_CONTROLLER_SOURCE_ROOT,commit,tree,
                            approval.evidence_sha256,binding,control_decision_ref)


def _provision_worker(store, *, request, change_id, authority, policy,
                      control_decision_ref, start_heartbeat=True):
    if store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0] != 10:
        raise pg.TypedPostgresError("POSTGRES_WORKER_REQUIRES_SCHEMA10")
    validate_schema(store.connection, target_version=10)
    kind = pg.TypedOperationType.EXECUTE_AUTHORIZED_SQL_FILE
    fingerprint = pg._request_fingerprint(
        change_id=change_id, control_decision_ref=control_decision_ref,
        deployment_id=request.operation_id, operation_type=kind,
        target_service=pg.CLEANER_TARGET_SERVICE, target_database=pg.CLEANER_DATABASE,
        principal_identity=WORKER_LOGIN, credential_reference=pg.CredentialReference.DBA_PGPASS,
        artifact_path=WORKER_SQL_PATH, artifact_sha256=WORKER_SQL_SHA256, request=request,
        expected_before_identity={"allowed": ["CREATE_EXACT", "COMPLETE_MEMBERSHIP", "NOOP_EXACT"]},
        desired_after_identity=_worker_expected_state())
    intent = pg._ReceiptIntent(change_id, control_decision_ref, request.operation_id,
        request.operation_id, kind, pg.CLEANER_TARGET_SERVICE, pg.CLEANER_DATABASE,
        WORKER_LOGIN, pg.CredentialReference.DBA_PGPASS, WORKER_SQL_PATH, WORKER_SQL_SHA256, fingerprint)
    replay = pg._replay_receipt_if_present(store, intent, factual_readback=lambda: _worker_state(policy),
        final_validator=lambda state: _validate_worker_state(state, final=True))
    if replay is not None:
        return replay
    receipts = []

    def effect():
        raw = _worker_artifact()
        pg._assert_current_typed_authority(store, authority, change_id=change_id, deployment_id=request.operation_id)
        before = _worker_state(policy)
        mode = _validate_worker_state(before)
        pg._persist_prepared_receipt(store, authority, intent, before)
        result=None
        if mode != "NOOP_EXACT":
            with _worker_pg_mutation(store,authority,change_id,request.operation_id):
                result=pg._run_psql(policy,database=pg.CLEANER_DATABASE,execution_role=pg.CLEANER_DBA_ROLE,
                    stdin_sql=raw,connection_credential=pg.CredentialReference.DBA_PGPASS)
        return pg._TypedEffectResult(kind, "NOOP_EXACT" if mode == "NOOP_EXACT" else "APPLIED",
                                    before, result, WORKER_SQL_PATH, WORKER_SQL_SHA256)

    run_controlled_deployment(store, change_id=change_id, deployment_id=request.operation_id,
        authority=authority, steps=(DeploymentStep("PROVISION_EXACT_CLEANER_WORKER", effect,
        lambda _result: _worker_state(policy)),), control_decision_ref=control_decision_ref,
        start_heartbeat=start_heartbeat,
        persist_result=lambda items: receipts.append(pg._persist_final_receipt(store, authority, intent, items)))
    if len(receipts) != 1:
        raise pg.TypedPostgresError("TYPED_POSTGRES_RECEIPT_MISSING")
    return receipts[0]


def provision_cleaner_worker_principal(*, change_id: str, request: CleanerWorkerRequest,
                                      control_decision_ref: str, gate_or_control_id: str):
    authority = _worker_approval(request, change_id, control_decision_ref, gate_or_control_id,
        entrypoint="provision_cleaner_worker_principal", kind="EXECUTE_AUTHORIZED_SQL_FILE",
        scopes=("CREATE_EXACT_CLEANER_WORKER_PRINCIPAL", "CREATE_EXACT_CLEANER_WORKER_MEMBERSHIP"),
        artifact={"path": WORKER_SQL_PATH, "sha256": WORKER_SQL_SHA256})
    policy = pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    with pg._canonical_typed_postgres_control_store() as store:
        return _provision_worker(store, request=request, change_id=change_id, authority=authority,
                                 policy=policy, control_decision_ref=control_decision_ref)


def _validate_worker_login_proof(proof):
    expected = dict(exists=True, role=WORKER_LOGIN, session_user=WORKER_LOGIN,
                    current_user=WORKER_CAPABILITY, database=pg.CLEANER_DATABASE)
    if not isinstance(proof,dict) or pg._state_fingerprint(proof) != pg._state_fingerprint(expected):
        raise pg.TypedPostgresError("POSTGRES_WORKER_LOGIN_ROLE_PROOF_FAILED")


def _worker_login_proof(policy):
    _validate_worker_state(_worker_state(policy), final=True)
    credential = pg._validate_credential(policy, WORKER_CREDENTIAL, reveal_text=True)
    secret = pg._password_from_credential(policy, credential)
    pg._validate_psql_binary(policy)
    # A clean libpq environment prevents ambient passwords/services from masking
    # the dedicated passfile. No query output or exception message is returned.
    if any(key.startswith("PG") for key in os.environ):
        raise pg.TypedPostgresError("POSTGRES_WORKER_AMBIENT_CREDENTIAL_FORBIDDEN")
    sql = ("SET ROLE propertyai_async_worker; SELECT json_build_object('exists',true,"
           "'role','propertyai_cleaner_worker','session_user',session_user,"
           "'current_user',current_user,'database',current_database())::text;").encode()
    try:
        result = pg._spawn_psql(policy, database=pg.CLEANER_DATABASE,
            execution_role=WORKER_LOGIN, stdin_sql=sql, credential=credential,
            connection_secret=secret, read_only=True)
        if result.exit_status != 0:
            raise ValueError()
        lines = [line for line in result.stdout.splitlines() if line.strip() and line != "SET"]
        if len(lines) != 1:
            raise ValueError()
        proof = json.loads(lines[0])
        _validate_worker_login_proof(proof)
        return proof
    except Exception:
        raise pg.TypedPostgresError("POSTGRES_WORKER_LOGIN_ROLE_PROOF_FAILED") from None
    finally:
        secret = ""


def _read_cleaner_worker_runtime_readiness():
    policy = pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    return _worker_login_proof(policy)


def _exclusive_json(path: Path, value):
    raw = json.dumps({**value,"created_at":datetime.now(timezone.utc).isoformat()},
                     sort_keys=True, separators=(",", ":")).encode()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(directory)
    except BaseException:
        # Keep partial evidence: interruption is not permission to replace it.
        raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_RECONCILIATION_REQUIRED") from None
    finally:
        os.close(directory)


def _credential_metadata(policy):
    path = policy.secret_dir / "worker.pgpass"
    if not path.exists() and not path.is_symlink():
        return {"exists": False}
    material = pg._validate_credential(policy, WORKER_CREDENTIAL, reveal_text=True)
    pg._password_from_credential(policy, material)
    # No content hash or password verifier is persisted.
    info = path.lstat()
    return dict(exists=True, reference=WORKER_CREDENTIAL.value, uid=info.st_uid,
                mode=stat.S_IMODE(info.st_mode), device=info.st_dev, inode=info.st_ino,
                size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)


def _credential_evidence_identity(request, change_id, control_decision_ref, authority):
    return dict(operation_id=request.operation_id, change_id=change_id,
        control_decision_ref=control_decision_ref, reference=WORKER_CREDENTIAL.value,
        controller_commit=authority.expected_head, controller_tree=getattr(authority,"tree",None),
        approval_evidence_sha256=getattr(authority,"approval_evidence_sha256",None),
        contract="DL98_W07_WORKER_CREDENTIAL_V1")


def _credential_paths(evidence_root, identity):
    # Stable operation location prevents a new approval/source from hiding old effects.
    name = pg._state_fingerprint({key:identity[key] for key in ("change_id","operation_id")})
    return tuple(evidence_root / (name + suffix) for suffix in (".prepared.json",".effect.json",".final.json"))


def _read_credential_reconciliation(policy, evidence_root, identity):
    documents = []
    for path,phase in zip(_credential_paths(evidence_root,identity),("PREPARED","EFFECT","FINAL")):
        if not path.exists() and not path.is_symlink():
            documents.append(None)
            continue
        info=pg._ensure_plain_file_no_symlink(path,code_prefix="WORKER_CREDENTIAL_EVIDENCE")
        if info.st_uid != policy.expected_secret_owner_uid or stat.S_IMODE(info.st_mode) != 0o600:
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_METADATA_INVALID")
        raw,_=pg._read_pinned_file(path,code_prefix="WORKER_CREDENTIAL_EVIDENCE")
        try:
            document=json.loads(raw)
        except Exception:
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_INVALID") from None
        if (not isinstance(document,dict) or document.get("phase")!=phase
            or any(document.get(k)!=v for k,v in identity.items())):
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_IDENTITY_DRIFT")
        documents.append(document)
    prepared,effect,final=documents
    try:
        metadata=_credential_metadata(policy)
    except pg.TypedPostgresError:
        return {"status":"PARTIAL_OR_INVALID_FILE_RECONCILIATION_REQUIRED"}
    if final is not None:
        if prepared is None or effect is None or final.get("metadata")!=metadata or effect.get("metadata")!=metadata:
            return {"status":"FINAL_READBACK_MISMATCH"}
        return {"status":"FINAL_PASS","metadata":metadata}
    if prepared is None:
        return {"status":"PRISTINE" if not metadata["exists"] and effect is None else "UNATTRIBUTED_FILE_RECONCILIATION_REQUIRED"}
    if not metadata["exists"]:
        return {"status":"PREPARED_FILE_ABSENT_RECONCILIATION_REQUIRED"}
    if effect is None or effect.get("metadata")!=metadata:
        return {"status":"VALID_FILE_WITHOUT_DURABLE_EFFECT_IDENTITY_RECONCILIATION_REQUIRED"}
    return {"status":"EFFECT_APPLIED_FINAL_MISSING","metadata":metadata}


def _create_worker_credential(store, *, request, change_id, authority, policy,
                              control_decision_ref, evidence_root, start_heartbeat=True):
    if store.connection.execute("SELECT max(version) FROM schema_migration").fetchone()[0] != 10:
        raise pg.TypedPostgresError("POSTGRES_WORKER_REQUIRES_SCHEMA10")
    validate_schema(store.connection, target_version=10)
    pg._ensure_directory_no_symlink(policy.secret_dir, expected_mode=0o700,
        expected_uid=policy.expected_secret_owner_uid, code_prefix="WORKER_SECRET_DIR")
    if evidence_root.exists() or evidence_root.is_symlink():
        pg._ensure_directory_no_symlink(evidence_root, expected_mode=0o700,
            expected_uid=policy.expected_secret_owner_uid, code_prefix="WORKER_EVIDENCE_DIR")
    identity = _credential_evidence_identity(request,change_id,control_decision_ref,authority)
    prepared, effect_evidence, final = _credential_paths(evidence_root,identity)
    if _read_credential_reconciliation(policy,evidence_root,identity)["status"] != "PRISTINE":
        raise pg.TypedPostgresError("WORKER_CREDENTIAL_EXISTING_STATE_RECONCILIATION_REQUIRED")

    def effect():
        token = pg._assert_current_typed_authority(store, authority,
            change_id=change_id, deployment_id=request.operation_id)
        if not evidence_root.exists():
            # One fixed evidence directory, no caller-selected parent creation.
            if evidence_root.parent.is_symlink() or not evidence_root.parent.is_dir():
                raise pg.TypedPostgresError("WORKER_EVIDENCE_PARENT_INVALID")
            evidence_root.mkdir(mode=0o700)
        pg._ensure_directory_no_symlink(evidence_root, expected_mode=0o700,
            expected_uid=policy.expected_secret_owner_uid, code_prefix="WORKER_EVIDENCE_DIR")
        _validate_worker_state(_worker_state(policy), final=True)
        if _credential_metadata(policy)["exists"]:
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_ALREADY_EXISTS")
        # Catalog/credential readback may block after entry; PREPARED requires
        # a fresh approval and W08 immediately after those reads.
        token=pg._assert_current_typed_authority(store,authority,
            change_id=change_id,deployment_id=request.operation_id)
        _exclusive_json(prepared, {**identity, "phase": "PREPARED", "w08_fence": token,
                                   "before": {"exists": False}})
        pg._assert_current_typed_authority(store, authority,
            change_id=change_id, deployment_id=request.operation_id)
        secret = secrets.token_hex(32)
        path = policy.secret_dir / "worker.pgpass"
        try:
            directory = os.open(policy.secret_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info=os.fstat(directory)
                if info.st_uid!=policy.expected_secret_owner_uid or stat.S_IMODE(info.st_mode)!=0o700:
                    raise pg.TypedPostgresError("WORKER_SECRET_DIR_METADATA_DRIFT")
                pg._assert_current_typed_authority(store,authority,
                    change_id=change_id,deployment_id=request.operation_id)
                fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,dir_fd=directory)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(f"{policy.host}:{policy.port}:{pg.CLEANER_DATABASE}:{WORKER_LOGIN}:{secret}\n".encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_EFFECT_RECONCILIATION_REQUIRED") from None
        finally:
            secret = ""
        metadata=_credential_metadata(policy)
        _exclusive_json(effect_evidence,{**identity,"phase":"EFFECT","metadata":metadata})
        return metadata

    def persist(items):
        pg._assert_current_typed_authority(store, authority,
            change_id=change_id, deployment_id=request.operation_id)
        if len(items) != 1 or items[0].effect_result != items[0].readback:
            raise pg.TypedPostgresError("WORKER_CREDENTIAL_READBACK_DRIFT")
        _exclusive_json(final, {**identity, "phase": "FINAL", "metadata": items[0].readback})

    return run_controlled_deployment(store, change_id=change_id, deployment_id=request.operation_id,
        authority=authority, control_decision_ref=control_decision_ref, start_heartbeat=start_heartbeat,
        steps=(DeploymentStep("CREATE_EXACT_WORKER_PROTECTED_CREDENTIAL", effect,
                              lambda _result: _credential_metadata(policy)),), persist_result=persist)


def create_cleaner_worker_protected_credential(*, change_id: str, request: CleanerWorkerRequest,
                                               control_decision_ref: str, gate_or_control_id: str):
    authority = _worker_approval(request, change_id, control_decision_ref, gate_or_control_id,
        entrypoint="create_cleaner_worker_protected_credential", kind="CREATE_WORKER_PROTECTED_CREDENTIAL",
        scopes=("CREATE_EXACT_WORKER_PROTECTED_CREDENTIAL",))
    policy = pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    with pg._canonical_typed_postgres_control_store() as store:
        return _create_worker_credential(store, request=request, change_id=change_id, authority=authority,
            policy=policy, control_decision_ref=control_decision_ref, evidence_root=WORKER_EVIDENCE_ROOT)


def reconcile_cleaner_worker_protected_credential(*, change_id: str, request: CleanerWorkerRequest,
                                                  control_decision_ref: str, gate_or_control_id: str):
    """Settle only a durable matching EFFECT, using its original live approval.

    Missing/partial/unattributed files are reported factually and never recreated.
    Renewed or differently bound approvals cannot silently adopt an old file.
    """
    authority=_worker_approval(request,change_id,control_decision_ref,gate_or_control_id,
        entrypoint="create_cleaner_worker_protected_credential",kind="CREATE_WORKER_PROTECTED_CREDENTIAL",
        scopes=("CREATE_EXACT_WORKER_PROTECTED_CREDENTIAL",))
    policy=pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    pg._ensure_directory_no_symlink(WORKER_EVIDENCE_ROOT,expected_mode=0o700,
        expected_uid=policy.expected_secret_owner_uid,code_prefix="WORKER_EVIDENCE_DIR")
    identity=_credential_evidence_identity(request,change_id,control_decision_ref,authority)
    status=_read_credential_reconciliation(policy,WORKER_EVIDENCE_ROOT,identity)
    if status["status"] != "EFFECT_APPLIED_FINAL_MISSING":
        return status
    # A consumed controlled-deployment identity is never reacquired. This is
    # one separate deterministic receipt-completion attempt, not a new secret.
    attempt=request.operation_id+":FINAL_RECONCILIATION:V1"
    with pg._canonical_typed_postgres_control_store() as store:
        def effect():
            pg._assert_current_typed_authority(store,authority,change_id=change_id,deployment_id=attempt)
            current=_read_credential_reconciliation(policy,WORKER_EVIDENCE_ROOT,identity)
            if current != status:
                raise pg.TypedPostgresError("WORKER_CREDENTIAL_RECONCILIATION_READBACK_DRIFT")
            return current
        def persist(items):
            pg._assert_current_typed_authority(store,authority,change_id=change_id,deployment_id=attempt)
            if len(items)!=1 or items[0].readback!=status:
                raise pg.TypedPostgresError("WORKER_CREDENTIAL_RECONCILIATION_READBACK_DRIFT")
            final=_credential_paths(WORKER_EVIDENCE_ROOT,identity)[2]
            _exclusive_json(final,{**identity,"phase":"FINAL","metadata":status["metadata"],
                                   "reconciliation_attempt":attempt})
        run_controlled_deployment(store,change_id=change_id,deployment_id=attempt,
            authority=authority,control_decision_ref=control_decision_ref,
            steps=(DeploymentStep("RECONCILE_EXACT_WORKER_CREDENTIAL_FINAL",effect,
                lambda _result:_read_credential_reconciliation(policy,WORKER_EVIDENCE_ROOT,identity)),),
            persist_result=persist)
    return _read_credential_reconciliation(policy,WORKER_EVIDENCE_ROOT,identity)


def read_cleaner_worker_credential_reconciliation(*, change_id: str, request: CleanerWorkerRequest):
    """Read original protected evidence after expiry, without approving any effect."""
    if type(request) is not CleanerWorkerRequest:
        raise pg.TypedPostgresError("TYPED_POSTGRES_PUBLIC_REQUEST_INVALID")
    pg._validate_control_identifiers(change_id,"DL98/WORKER/RECONCILIATION",request.operation_id)
    policy=pg._canonical_cleaner_postgres_policy()
    pg._validate_sealed_canonical_policy(policy)
    if not WORKER_EVIDENCE_ROOT.exists() and not WORKER_EVIDENCE_ROOT.is_symlink():
        exists=_credential_metadata(policy)["exists"]
        return {"status":"UNATTRIBUTED_FILE_RECONCILIATION_REQUIRED" if exists else "PRISTINE",
                "effect_authorization":"NOT_GRANTED_BY_READBACK"}
    pg._ensure_directory_no_symlink(WORKER_EVIDENCE_ROOT,expected_mode=0o700,
        expected_uid=policy.expected_secret_owner_uid,code_prefix="WORKER_EVIDENCE_DIR")
    seed={"change_id":change_id,"operation_id":request.operation_id}
    path=_credential_paths(WORKER_EVIDENCE_ROOT,seed)[0]
    if not path.exists() and not path.is_symlink():
        return {"status":"NO_PREPARED_EVIDENCE", "credential_exists":_credential_metadata(policy)["exists"]}
    info=pg._ensure_plain_file_no_symlink(path,code_prefix="WORKER_CREDENTIAL_EVIDENCE")
    if info.st_uid!=policy.expected_secret_owner_uid or stat.S_IMODE(info.st_mode)!=0o600:
        raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_METADATA_INVALID")
    raw,_=pg._read_pinned_file(path,code_prefix="WORKER_CREDENTIAL_EVIDENCE")
    try:
        document=json.loads(raw)
        keys=("operation_id","change_id","control_decision_ref","reference","controller_commit",
              "controller_tree","approval_evidence_sha256","contract")
        identity={key:document[key] for key in keys}
        if (identity["change_id"]!=change_id or identity["operation_id"]!=request.operation_id
            or identity["reference"]!=WORKER_CREDENTIAL.value
            or identity["contract"]!="DL98_W07_WORKER_CREDENTIAL_V1"):
            raise ValueError()
        for key,length in (("controller_commit",40),("controller_tree",40),("approval_evidence_sha256",64)):
            value=identity[key]
            if not isinstance(value,str) or len(value)!=length or any(c not in "0123456789abcdef" for c in value):
                raise ValueError()
    except Exception:
        raise pg.TypedPostgresError("WORKER_CREDENTIAL_EVIDENCE_IDENTITY_INVALID") from None
    return {**_read_credential_reconciliation(policy,WORKER_EVIDENCE_ROOT,identity),
            "original_controller_commit":identity["controller_commit"],
            "original_approval_evidence_sha256":identity["approval_evidence_sha256"],
            "effect_authorization":"NOT_GRANTED_BY_READBACK"}
