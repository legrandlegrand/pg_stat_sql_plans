/* contrib/pg_stat_sql_plans/pg_stat_sql_plans--0.2.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_stat_sql_plans" to load this file. \quit

-- Register functions.
CREATE FUNCTION pg_stat_sql_plans_reset()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C PARALLEL SAFE;

CREATE FUNCTION pgssp_normalize_query(text)
RETURNS text
AS 'MODULE_PATHNAME'
LANGUAGE C
RETURNS NULL ON NULL INPUT;

CREATE FUNCTION pg_stat_sql_plans(IN showtext boolean,
    OUT userid oid,
    OUT dbid oid,
    OUT qpid int8,
    OUT query text,
    OUT queryid int8,
    OUT planid int8,
    OUT plans int8,
    OUT calls int8,
    OUT total_time float8,
    OUT min_time float8,
    OUT max_time float8,
    OUT mean_time float8,
    OUT stddev_time float8,
    OUT plan_time float8,
    OUT exec_time float8,
    OUT extn_time float8,
    OUT rows int8,
    OUT shared_blks_hit int8,
    OUT shared_blks_read int8,
    OUT shared_blks_dirtied int8,
    OUT shared_blks_written int8,
    OUT local_blks_hit int8,
    OUT local_blks_read int8,
    OUT local_blks_dirtied int8,
    OUT local_blks_written int8,
    OUT temp_blks_read int8,
    OUT temp_blks_written int8,
    OUT blk_read_time float8,
    OUT blk_write_time float8,
    OUT first_call timestamptz,
    OUT last_call timestamptz
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_stat_sql_plans_1_3'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

-- Register a view on the function for ease of use.
CREATE VIEW pg_stat_sql_plans AS
SELECT 
	* 
FROM pg_stat_sql_plans(true)
;

create view public.pg_stat_sql_plans_agg as 
SELECT
	pgssp.userid,
	pgssp.dbid,
	pgssp.queryid,
	count(case when pgssp.planid != 0 then pgssp.planid end )  as distinct_planid,
	STRING_AGG(case when pgssp.planid != 0 then pgssp.planid::text end , ',')  as planids,
	max(pgssp.query) query,
	sum(pgssp.plans) as plans,
	sum(pgssp.calls) as calls,
	sum(total_time) as total_time,
	sum(pgssp.plan_time) as plan_time,
	sum(pgssp.exec_time) as exec_time,
	sum(pgssp.extn_time) as extn_time,
	sum(total_time)/sum(pgssp.calls) as average_time,
	sum(pgssp.plan_time)/sum(case when pgssp.plans = 0 then 1 else pgssp.plans end ) as plan_avg_time,
	sum(pgssp.exec_time)/sum(pgssp.calls) as exec_avg_time,
	sum(pgssp.extn_time)/sum(pgssp.calls) as extn_avg_time,
	sum(pgssp.rows) as rows,
	min(pgssp.first_call) as first_call,
	max(pgssp.last_call) as last_call
FROM
	public.pg_stat_sql_plans(true) pgssp
WHERE
	pgssp.calls !=0
GROUP BY
	pgssp.userid,
	pgssp.dbid,
	pgssp.queryid;

GRANT SELECT ON pg_stat_sql_plans,pg_stat_sql_plans_agg TO PUBLIC;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_stat_sql_plans_reset() FROM PUBLIC;

CREATE FUNCTION pgssp_backend_qpid(int)
RETURNS int8
AS 'MODULE_PATHNAME'
LANGUAGE C
RETURNS NULL ON NULL INPUT;
