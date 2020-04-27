# pg_stat_sql_plans
pg_stat_sql_plans is a PostgreSQL extension created from pg_stat_statements to add a planid column making it closer to Oracle V$SQL view.

Alpha version, DO NOT USE IN PRODUCTION

# Content:

	Customized version of pg_stat_statements, implementing many Oracle like features:
		- queryid is based on normalized sql text,
		- query text is not normalized (but a SQL function is provided to do so),
		- planid is based on normalized explain text,
		- explain text is saved in logs,
		- first_call, last_call informations are kept for each entry,
		- contains duration of queries not finished in success (timeout, error, cancelled, ...),
		- contains duration of planning,
		- queryid is available in pg_stat_activity for each pid,
		- includes specific wait events for planing and extension activities,
		- ...

	Some ideas where found in other postgres extensions like pg_store_plans, pg_stat_plans
	auto_explain, ... and patches from pgsql-hackers mailing list.


# Prerequisites:
	Postgres version >= 11 and < 13
	should be declared in postgresql.conf with shared_preload_libraries='pg_stat_sql_plans'


# View pg_stat_sql_plans definition:

	userid
		see pg_stat_statements
	dbid
		see pg_stat_statements

	queryid
		hash value of normalized query text (using pgssp_normalize_query(text))
		Queryid is constant between different environments, and doen't change
		after object recreation (after drop create or dump/restore)

	planid
		hash value of normalized plan text (using pgssp_normalize_query(text))
		verbose OFF, may be changed in verbose ON to display objects schemas
		Default	values:
       -1 for planning duration (hidden in this view but available in pg_stat_sql_plans(true)),
        0 for utility statement,
        1 when track_planid = false ,
        765585858645765476 when track_planid = true

	query
		text (not normalized, with constant values) of the first query for stored
		(queryid, planid). This text can be reused to generate explain plans or
		normalied with function pgssp_normalize_query(text)

	calls
		see pg_stat_statements
	...

	plan_time
		only for planid = -1 
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
	
	plan_calls
		number of planning executions
		
	exec_calls
		number of executions
		
	total_time
		total time of planning + execution + extension
		
	plan_tot_time
	exec_tot_time
	extn_tot_time
	
	average_time
		total_time / exec_calls
		
	plan_avg_time
		plan_tot_time / plan_calls

	exec_avg_time
		exec_tot_time / exec_calls

	extn_avg_time
		extn_tot_time / exec_calls

	rows
	first_call
	last_call

# Parameters (GUC):
	(*) means default value:

	pg_stat_sql_plans.explain true, false (*)
		write the plan in log file (as auto_explain) for new queries queryid/planid

	pg_stat_sql_plans.max 5000 (*)
	pg_stat_sql_plans.save true (*), false
	pg_stat_sql_plans.track top (*), all, none

	pg_stat_sql_plans.track_errors true (*), false
		include duration of queries not finished in success (timeout, error, cancelled, ...)

	pg_stat_sql_plans.track_planid true (*), false

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

	- pgssp_backend_queryid(pid)
		last queryid executed by backend, not top query like pl/pgsql, but the active one.
		usefull for sampling wait events per process and or queryid

		returns 0 if no queryid found.


# Wait events:
	- extension event
		event_type-event_name "Extension"-"Extension" is displayed when
		spending time in pgssp_store function including:
			- time to store entry,
			- planid calculation (that can be long on table with many columns),
			- old entries eviction

	- planing event
		During planning event_type-event_name  "Activity"-"unknown wait event"
		are displayed.


# Examples
	- join pg_stat_activity with pg_stat_sql_plans on (dbid,userid, queryid)

		SELECT
			pgsa.datname,
			pgsa.pid,
			pgsa.usename,
			pgsa.application_name,
			pgsa.client_port,
			pgsa.backend_type,
			pgsa.backend_start,
			pgsa.query_start,
			pgsa.wait_event_type,
			pgsa.wait_event,
			pgsa.state,
			pgsa.query,
			pgssp_backend_queryid( pgsa.pid ),
			pgssp.query,
			pgssp.calls
		FROM
			pg_stat_activity pgsa
				LEFT OUTER JOIN pg_stat_sql_plans pgssp
			 ON  pgssp_backend_queryid( pgsa.pid ) = pgssp.queryid
			 AND pgsa.datid = pgssp.dbid
			 AND pgsa.usesysid = pgssp.userid
		WHERE pgsa.state='active'
		;


	- sampling wait events pg_stat_activity per queryid

		create table mon as
		SELECT pid,wait_event_type,wait_event,pgssp_backend_queryid( pid ) as queryid
			FROM pg_stat_activity
			WHERE state = 'active' and pid != pg_backend_pid()
		;

		DO
		$$
		DECLARE
			i int;
		BEGIN
			while true
			loop
				INSERT into mon select pid,wait_event_type,wait_event,pgssp_backend_queryid( pid )
					FROM pg_stat_activity
					WHERE state ='active' and pid != pg_backend_pid();
				PERFORM pg_sleep(0.01);
				COMMIT;
			end loop;
		END
		$$
		;
