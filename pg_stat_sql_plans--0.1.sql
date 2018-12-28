/* contrib/pg_stat_sql_plans/pg_stat_sql_plans--0.1.sql */

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
    OUT queryid int8,
    OUT planid int8,
    OUT query text,
    OUT calls int8,
    OUT total_time float8,
    OUT min_time float8,
    OUT max_time float8,
    OUT mean_time float8,
    OUT stddev_time float8,
    OUT plan_time float8,
    OUT exec_time float8,
    OUT pgss_time float8,
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
FROM pg_stat_sql_plans(true);
  
create view public.pg_stat_sql_times as 
SELECT
	pgssp.userid,
	pgssp.dbid,
	pgssp.queryid,
	count(case when pgssp.planid not in (0,-1) then pgssp.planid end )  as planid_nb,
	STRING_AGG(case when pgssp.planid != -1 then pgssp.planid::text end , ',')  as planid_list,
	max(pgssp.query) query,
	sum(case when pgssp.planid = -1 then pgssp.calls end) as plan_calls,
	sum(case when pgssp.planid != -1 then pgssp.calls end) as exec_calls,
	sum(pgssp.plan_time) as tot_plan_time,
	sum(pgssp.exec_time) as tot_exec_time,
	sum(pgssp.pgss_time) as tot_pgss_time,
	sum(pgssp.pgss_time)+sum(pgssp.exec_time)+sum(pgssp.plan_time) as tot_time,
	sum(pgssp.plan_time)/sum(case when pgssp.planid = -1 then pgssp.calls end) as avg_plan_time,
	sum(pgssp.exec_time)/sum(case when pgssp.planid != -1 then pgssp.calls end) as avg_exec_time,
	sum(pgssp.pgss_time)/sum(case when pgssp.planid != -1 then pgssp.calls end) as avg_pgss_time,
	()sum(pgssp.pgss_time)+sum(pgssp.exec_time)+sum(pgssp.plan_time))/sum(case when pgssp.planid != -1 then pgssp.calls end) as avg_time,
	sum(pgssp.rows) as rows,
	min(pgssp.first_call) as first_call,
	max(pgssp.last_call) as last_call
FROM
	public.pg_stat_sql_plans(true) pgssp
group by
	pgssp.userid,
	pgssp.dbid,
	pgssp.queryid;

GRANT SELECT ON pg_stat_sql_plans,pg_stat_sql_time TO PUBLIC;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_stat_sql_plans_reset() FROM PUBLIC;

CREATE FUNCTION pgssp_backend_queryid(int)
RETURNS int8
AS 'MODULE_PATHNAME'
LANGUAGE C
RETURNS NULL ON NULL INPUT;
