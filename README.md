# pg_stat_sql_plans
pg_stat_sql_plans is a PostgreSQL extension created from pg_stat_statements adding a planid column 
generated from the hash value of the explain text.

Alpha version, DO NOT USE IN PRODUCTION

# Content:

	Customized version of pg_stat_statements, implementing many additionnal features:
		- queryid is based on normalized sql text (not parse tree jumbling),
		- stored query text is not normalized (but a SQL function is provided to do so),
		- planid is based on normalized explain text,
		- includes a specific 'minimal' explain module, for performances,
		- planid is build at planning time, making it reusable by cached plans,
		- explain text is saved in logs,
		- first_call, last_call informations are kept for each entry,
		- contains duration of queries that failed (timeout, error, cancelled, ...),
		- contains duration of planning,
		- expose current queryid, planid per pid in pg_stat_activity,
		- includes specific wait events for planning and extension activities,
		- ...

	Some ideas where found in other postgres extensions like pg_store_plans, pg_stat_plans
	auto_explain, pg_show_plans ... and patches from pgsql-hackers mailing list.


# Prerequisites:
	Postgres version >= 14 (see other branch for pg11-12 and pg13 compatiblility)
	should be declared in postgresql.conf with shared_preload_libraries='pg_stat_sql_plans'
	and compute_query_id = off (to bypass core query_id computation)


# View pg_stat_sql_plans definition:

	userid
		see pg_stat_statements

	dbid
		see pg_stat_statements

	qpid
		query plan id, combining (queryid,planid) values

	query
		text (not normalized, with constant values) of the first query for a qpid
		(queryid, planid). This text can be reused to generate explain plans or
		normalized with function pgssp_normalize_query(text)

	queryid
		hash value of normalized query text (using pgssp_normalize_query(text))
		queryid is stable across different databases / environments, and doen't 
		change after object recreation (after drop create or dump/restore)

	planid
		hash value of normalized plan text (using pgssp_normalize_query(text))
		obtained with EXPLAIN 
			costs OFF (for performances reasons),
			verbose OFF (may be changed in verbose ON to display objects schemas)
		Default	values:
			0 for utility statement (Optimisable one's like "CREATE TABLE AS"
			  have a planid calculated and an explain plan like any other query) 
			1 when plan_type = 'none'
			765585858645765476 when plan_type = 'standard'


	plans
		see pg_stat_statements

	calls
		see pg_stat_statements
	...

	plan_time
		planning time (milli seconds)
	exec_time
		execution time as found in pg_statements extension.
	extn_time
		time spent by extension in pgssp_store function (including planid calculation)
	...

	first_call
		first occurence date of the line
	last_call
		latest occurence date of the line

# View pg_stat_sql_plans_agg definition:
	
	userid
	
	dbid
	
	queryid
	
	distinct_planid 
		number of distinct planid for this query
		
	planids
		list of the planid for this query
		
	query
	
	plans
		number of planning executions
		
	calls
		number of executions
		
	total_time
		total time of planning + execution + extension
		
	plan_time
	exec_time
	extn_time
	
	average_time
		total_time / calls
		
	plan_avg_time
		plan_time / plans

	exec_avg_time
		exec_time / calls

	extn_avg_time
		extn_time / calls

	rows
	first_call
	last_call

# Parameters (GUC):
	(*) means default value:

	pg_stat_sql_plans.explain true, false (*)
		write the plan in log file (as auto_explain) for each new (queryid,planid)

	pg_stat_sql_plans.max 5000 (*)

	pg_stat_sql_plans.plan_type none, standard (*) 
		none: plan is not considered, planid=1
		standard: use native explain with costs OFF, verbose OFF, can be slow

	pg_stat_sql_plans.save true (*), false

	pg_stat_sql_plans.track top (*), all, none

	pg_stat_sql_plans.track_errors true (*), false 
		include duration of failed queries (timeout, error, cancelled, ...)

	pg_stat_sql_plans.track_pid true (*), false
		enable, disable the result of pgssp_backend_qpid(pid), can only by changed at the db level
		using pg_relaod_conf().

	pg_stat_sql_plans.track_utility true (*), false


# Entries Eviction:
	based on oldest last_call date (to be sure to keep lastest recently used entries)
	a message is written in log file at each eviction pass like:
		"2018-11-13 22:16:36.421 CET [5904] LOG:  pg_stat_sql_plans evicting 250 entries"


# Additional Functions:
	- pg_stat_sql_plans_reset()
		to reset all entries.

	- pgssp_normalize_query(text)
		replace litérals and numerics per ?

	- pgssp_backend_qpid(pid)
		Returns last (nested) query plan id executing/executed by backend. 
		It returns queryid value during planning, and planid calculation. 
		This value does not reflect statements with syntax error (that are not parsed).
		Usefull to identify the query plan of a never ending query (without cancelling it)
		Also usefull for sampling wait events per queryid/planid, can be used to join
		pg_stat_activity with pg_stat_sql_plans (see exemple)

		returns 0 if no qpid found, -1 when trackin is disabled (pg_stat_sql_plans.track_pid = false)


# Wait events:
	- extension event
		event_type-event_name "Extension"-"Extension" is displayed when
		spending time in pgssp_store function including:
			- time to store entry,
			- planid calculation (that can be long on table with many columns),
			- old entries eviction

	- planning event
		During planning event_type-event_name  "Activity"-"unknown wait event"
		are displayed.


# Examples
	- join pg_stat_activity with pg_stat_sql_plans on (dbid,userid, qpid)

		SELECT
			pgsa.datname,
			pgsa.pid,
			pgsa.usename,
			pgsa.application_name,
			pgsa.state,
			pgsa.query,
			coalesce(queryid,pgsa.qpid) queryid,
			pgssp.planid,
			pgssp_normalize_query(pgssp.query),
			pgssp.calls
		FROM
			(SELECT *, pgssp_backend_qpid(pid) qpid FROM pg_stat_activity) pgsa
				LEFT OUTER JOIN pg_stat_sql_plans pgssp
			 ON  pgsa.qpid = pgssp.qpid
			 AND pgsa.datid = pgssp.dbid
			 AND pgsa.usesysid = pgssp.userid
		WHERE pgsa.backend_type='client backend'
		AND pgsa.pid != pg_backend_pid()
		;


	- sampling wait events pg_stat_activity per query plan id

		CREATE UNLOGGED TABLE mon AS
		SELECT pid,wait_event_type,wait_event,pgssp_backend_qpid(pid) AS qpid
			FROM pg_stat_activity
			WHERE 0=1
		;

		DO $$
		BEGIN
			LOOP
				INSERT INTO mon SELECT pid,wait_event_type,wait_event,pgssp_backend_qpid(pid)
					FROM pg_stat_activity
					WHERE state ='active' and pid != pg_backend_pid();
				PERFORM pg_sleep(0.01);
				COMMIT;
			END LOOP;
		END;
		$$
		;
