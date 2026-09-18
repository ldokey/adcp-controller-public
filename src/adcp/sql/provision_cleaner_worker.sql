-- DL98 fixed worker principal; not a schema migration or generic role executor.
DO $dl98_worker$
BEGIN
  SET LOCAL lock_timeout = '5s';
  LOCK TABLE pg_catalog.pg_authid, pg_catalog.pg_auth_members IN SHARE ROW EXCLUSIVE MODE;
  IF current_database() <> 'propertyai_cleaner_prod' OR
     current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'WORKER_TARGET_INVALID';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='propertyai_async_worker'
    AND NOT rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb
    AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=-1)
    OR EXISTS (SELECT FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.member
      WHERE r.rolname='propertyai_async_worker') THEN
    RAISE EXCEPTION 'WORKER_CAPABILITY_DRIFT';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_database d,
    LATERAL aclexplode(COALESCE(d.datacl, acldefault('d',d.datdba))) a
    WHERE d.datname='propertyai_cleaner_prod' AND a.grantee=0 AND a.privilege_type='CONNECT') THEN
    RAISE EXCEPTION 'WORKER_CONNECT_DRIFT';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker') THEN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker'
      AND rolcanlogin AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls AND rolconnlimit=-1) THEN
      RAISE EXCEPTION 'WORKER_PRINCIPAL_DRIFT';
    END IF;
  ELSE
    CREATE ROLE propertyai_cleaner_worker LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
      NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1;
  END IF;
  IF EXISTS (SELECT FROM (
    SELECT datdba AS owner, datacl AS acl FROM pg_catalog.pg_database
    UNION ALL SELECT nspowner, nspacl FROM pg_catalog.pg_namespace
    UNION ALL SELECT relowner, relacl FROM pg_catalog.pg_class
    UNION ALL SELECT 0::oid, attacl FROM pg_catalog.pg_attribute
    UNION ALL SELECT proowner, proacl FROM pg_catalog.pg_proc
    ) objects LEFT JOIN LATERAL aclexplode(objects.acl) a ON true
    WHERE objects.owner=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker')
       OR a.grantee=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname='propertyai_cleaner_worker')) THEN
    RAISE EXCEPTION 'WORKER_DIRECT_PRIVILEGE_DRIFT';
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles g ON g.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member
    WHERE (u.rolname='propertyai_cleaner_worker' OR g.rolname='propertyai_cleaner_worker'
      OR g.rolname='propertyai_async_worker')
      AND NOT (g.rolname='propertyai_async_worker' AND u.rolname='propertyai_cleaner_worker'
        AND NOT m.inherit_option AND m.set_option AND NOT m.admin_option)) THEN
    RAISE EXCEPTION 'WORKER_MEMBERSHIP_DRIFT';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles g ON g.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member
    WHERE g.rolname='propertyai_async_worker' AND u.rolname='propertyai_cleaner_worker') THEN
    GRANT propertyai_async_worker TO propertyai_cleaner_worker WITH INHERIT FALSE, SET TRUE, ADMIN FALSE;
  END IF;
  IF (SELECT count(*) FROM pg_catalog.pg_auth_members m
    JOIN pg_catalog.pg_roles g ON g.oid=m.roleid JOIN pg_catalog.pg_roles u ON u.oid=m.member
    WHERE g.rolname='propertyai_async_worker' OR u.rolname='propertyai_cleaner_worker'
       OR g.rolname='propertyai_cleaner_worker') <> 1 THEN
    RAISE EXCEPTION 'WORKER_MEMBERSHIP_AMBIGUOUS';
  END IF;
END; $dl98_worker$;
