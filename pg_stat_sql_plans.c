/*-------------------------------------------------------------------------
 *
 * pg_stat_sql_plans.c
 *		Track statement execution times across a whole database cluster.
 *
 * Execution costs are totalled for each distinct source query, and kept in
 * a shared hashtable.  (We track only as many distinct queries as will fit
 * in the designated amount of shared memory.)
 *
 * As of Postgres 9.2, this module normalizes query entries.  Normalization
 * is a process whereby similar queries, typically differing only in their
 * constants (though the exact rules are somewhat more subtle than that) are
 * recognized as equivalent, and are tracked as a single entry.  This is
 * particularly useful for non-prepared queries.
 *
 * To save on shared memory, and to avoid having to truncate oversized query 
 * strings, we store these strings in a temporary external query-texts file.
 * Offsets into this file are kept in shared memory.
 *
 * Note about locking issues: to create or delete an entry in the shared
 * hashtable, one must hold pgssp->lock exclusively.  Modifying any field
 * in an entry except the counters requires the same.  To look up an entry,
 * one must hold the lock shared.  To read or update the counters within
 * an entry, one must hold the lock shared or exclusive (so the entry doesn't
 * disappear!) and also take the entry's mutex spinlock.
 * The shared state variable pgssp->extent (the next free spot in the external
 * query-text file) should be accessed only while holding either the
 * pgssp->mutex spinlock, or exclusive lock on pgssp->lock.  We use the mutex to
 * allow reserving file space while holding only shared lock on pgssp->lock.
 * Rewriting the entire external query-text file, eg for garbage collection,
 * requires holding pgssp->lock exclusively; this allows individual entries
 * in the file to be read or written while holding only shared lock.
 *
 *
 * Copyright (c) 2008-2018, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/pg_stat_sql_plans/pg_stat_sql_plans.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <math.h>
#include <sys/stat.h>
#include <unistd.h>

#include "access/hash.h"
#include "access/twophase.h"
#include "catalog/pg_authid.h"
#include "commands/explain.h"
#include "executor/instrument.h"
#include "funcapi.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "parser/parsetree.h"
#include "parser/scanner.h"
#include "parser/scansup.h"
#include "parser/gram.h"
#include "pgstat.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "storage/spin.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"


PG_MODULE_MAGIC;

/* Location of permanent stats file (valid when database is shut down) */
#define pgssp_DUMP_FILE	PGSTAT_STAT_PERMANENT_DIRECTORY "/pg_stat_sql_plans.stat"

/*
 * Location of external query text file.  We don't keep it in the core
 * system's stats_temp_directory.  The core system can safely use that GUC
 * setting, because the statistics collector temp file paths are set only once
 * as part of changing the GUC, but pg_stat_sql_plans has no way of avoiding
 * race conditions.  Besides, we only expect modest, infrequent I/O for query
 * strings, so placing the file on a faster filesystem is not compelling.
 */
#define pgssp_TEXT_FILE	PG_STAT_TMP_DIR "/pgssp_query_texts.stat"

/* Magic number identifying the stats file format */
static const uint32 pgssp_FILE_HEADER = 0x20171004;

/* PostgreSQL major version number, changes in which invalidate all entries */
static const uint32 pgssp_PG_MAJOR_VERSION = PG_VERSION_NUM / 100;

/* XXX: Should USAGE_EXEC reflect execution time and/or buffer usage? */
//#define USAGE_EXEC(duration)	(1.0)
//#define USAGE_INIT				(1.0)	/* including initial planning */
#define ASSUMED_MEDIAN_INIT		(10.0)	/* initial assumed median usage */
#define ASSUMED_LENGTH_INIT		1024	/* initial assumed mean query length */
//#define USAGE_DECREASE_FACTOR	(0.99)	/* decreased every entry_dealloc */
//#define STICKY_DECREASE_FACTOR	(0.50)	/* factor for sticky entries */
#define USAGE_DEALLOC_PERCENT	5	/* free this % of entries at once */

/*
 * Extension version number, for supporting older extension versions' objects
 */
typedef enum pgsspVersion
{
	pgssp_V1_0 = 0,
	pgssp_V1_1,
	pgssp_V1_2,
	pgssp_V1_3
} pgsspVersion;

/*
 * Hashtable key that defines the identity of a hashtable entry.  We separate
 * queries by user and by database even if they are otherwise identical.
 *
 * Right now, this structure contains no padding.  If you add any, make sure
 * to teach pgssp_store() to zero the padding bytes.  Otherwise, things will
 * break, because pgssp_hash is created using HASH_BLOBS, and thus tag_hash
 * is used to hash this.
 */
typedef struct pgsspHashKey
{
	Oid			userid;			/* user OID */
	Oid			dbid;			/* database OID */
	uint64		queryid;		/* query identifier */
	uint64		planid;			/* plan identifier */
} pgsspHashKey;

/*
 * The actual stats counters kept within pgsspEntry.
 */
typedef struct Counters
{
	int64		calls;			/* # of times executed */
	double		total_time;		/* total execution time, in msec */
	double		min_time;		/* minimum execution time in msec */
	double		max_time;		/* maximum execution time in msec */
	double		mean_time;		/* mean execution time in msec */
	double		sum_var_time;	/* sum of variances in execution time in msec */
	double		plan_time;		/* total planing time, in msec */
	double		exec_time;		/* total execution time, in msec */
	double		pgssp_time;		/* total pgssp time, in msec */
	int64		rows;			/* total # of retrieved or affected rows */
	int64		shared_blks_hit;	/* # of shared buffer hits */
	int64		shared_blks_read;	/* # of shared disk blocks read */
	int64		shared_blks_dirtied;	/* # of shared disk blocks dirtied */
	int64		shared_blks_written;	/* # of shared disk blocks written */
	int64		local_blks_hit; /* # of local buffer hits */
	int64		local_blks_read;	/* # of local disk blocks read */
	int64		local_blks_dirtied; /* # of local disk blocks dirtied */
	int64		local_blks_written; /* # of local disk blocks written */
	int64		temp_blks_read; /* # of temp blocks read */
	int64		temp_blks_written;	/* # of temp blocks written */
	double		blk_read_time;	/* time spent reading, in msec */
	double		blk_write_time; /* time spent writing, in msec */
	TimestampTz	first_call;			/* timestamp of first call  */
	TimestampTz	last_call;			/* timestamp of last call  */
} Counters;

/*
 * Statistics per statement
 *
 * Note: in event of a failure in garbage collection of the query text file,
 * we reset query_offset to zero and query_len to -1.  This will be seen as
 * an invalid state by qtext_fetch().
 */
typedef struct pgsspEntry
{
	pgsspHashKey key;			/* hash key of entry - MUST BE FIRST */
	Counters	counters;		/* the statistics for this query */
	Size		query_offset;	/* query text offset in external file */
	int			query_len;		/* # of valid bytes in query string, or -1 */
	int			encoding;		/* query text encoding */
	slock_t		mutex;			/* protects the counters only */
} pgsspEntry;

/*
 * Global shared state
 */
typedef struct pgsspSharedState
{
	LWLock	   *lock;			/* protects hashtable search/modification */
	double		cur_median_usage;	/* current median usage in hashtable */
	Size		mean_query_len; /* current mean entry text length */
	slock_t		mutex;			/* protects following fields only: */
	Size		extent;			/* current extent of query file */
	int			n_writers;		/* number of active writers to query file */
	int			gc_count;		/* query file garbage collection cycle count */
} pgsspSharedState;

/*
 * Struct for tracking locations/lengths of constants during normalization
 */
typedef struct pgsspLocationLen
{
	int			location;		/* start offset in query text */
	int			length;			/* length in bytes, or -1 to ignore */
} pgsspLocationLen;

/* get max procs */
static int get_max_procs_count(void);

/* Proc entry */
typedef struct procEntry
{
	uint64 queryid;
} procEntry;
/*---- Local variables ----*/

/* Current nesting depth of ExecutorRun+ProcessUtility calls */
static int	nested_level = 0;

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;
static post_parse_analyze_hook_type prev_post_parse_analyze_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Links to shared memory state */
static pgsspSharedState *pgssp = NULL;
static HTAB *pgssp_hash = NULL;

/*---- GUC variables ----*/

typedef enum
{
	pgssp_TRACK_NONE,			/* track no statements */
	pgssp_TRACK_TOP,				/* only top level statements */
	pgssp_TRACK_ALL				/* all statements, including nested ones */
}			pgsspTrackLevel;

static const struct config_enum_entry track_options[] =
{
	{"none", pgssp_TRACK_NONE, false},
	{"top", pgssp_TRACK_TOP, false},
	{"all", pgssp_TRACK_ALL, false},
	{NULL, 0, false}
};

static int	pgssp_max;			/* max # statements to track */
static int	pgssp_track;			/* tracking level */
static bool pgssp_track_utility; /* whether to track utility commands */
static bool pgssp_track_errors;  /* whether to track statements in error */
static bool pgssp_track_planid; 	/* whether to track plan id */
static bool pgssp_explain;	 	/* whether to explain query */
static bool pgssp_save;			/* whether to save stats across shutdown */


#define pgssp_enabled() \
	(pgssp_track == pgssp_TRACK_ALL || \
	(pgssp_track == pgssp_TRACK_TOP && nested_level == 0))

#define record_gc_qtexts() \
	do { \
		volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp; \
		SpinLockAcquire(&s->mutex); \
		s->gc_count++; \
		SpinLockRelease(&s->mutex); \
	} while(0)

/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

PG_FUNCTION_INFO_V1(pg_stat_sql_plans_reset);
PG_FUNCTION_INFO_V1(pg_stat_sql_plans_1_2);
PG_FUNCTION_INFO_V1(pg_stat_sql_plans_1_3);
PG_FUNCTION_INFO_V1(pg_stat_sql_plans);
PG_FUNCTION_INFO_V1(pgssp_normalize_query);
PG_FUNCTION_INFO_V1(pgssp_backend_queryid);


static void pgssp_shmem_startup(void);
static void pgssp_shmem_shutdown(int code, Datum arg);
static PlannedStmt *pgssp_planner(Query *parse, int cursorOptions,
 				 ParamListInfo boundParams);
static void pgssp_post_parse_analyze(ParseState *pstate, Query *query);
static void pgssp_ExecutorStart(QueryDesc *queryDesc, int eflags);
static void pgssp_ExecutorRun(QueryDesc *queryDesc,
				 ScanDirection direction,
				 uint64 count, bool execute_once);
static void pgssp_ExecutorFinish(QueryDesc *queryDesc);
static void pgssp_ExecutorEnd(QueryDesc *queryDesc);
static void pgssp_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
					ProcessUtilityContext context, ParamListInfo params,
					QueryEnvironment *queryEnv,
					DestReceiver *dest, char *completionTag);
static uint64 pgssp_hash_string(const char *str, int len);
static void pgssp_store(const char *query, uint64 queryId, QueryDesc *queryDesc,
		   int query_location, int query_len,
		   double total_time, uint64 rows,
		   const BufferUsage *bufusage);
static void pg_stat_sql_plans_internal(FunctionCallInfo fcinfo,
							pgsspVersion api_version,
							bool showtext);
static Size pgssp_memsize(void);
static pgsspEntry *entry_alloc(pgsspHashKey *key, Size query_offset, int query_len,
			int encoding);
static void entry_dealloc(void);
static bool qtext_store(const char *query, int query_len,
			Size *query_offset, int *gc_count);
static char *qtext_load_file(Size *buffer_size);
static char *qtext_fetch(Size query_offset, int query_len,
			char *buffer, Size buffer_size);
static bool need_gc_qtexts(void);
static void gc_qtexts(void);
static void entry_reset(void);
void normalize_expr(char *expr, bool preserve_space);
static uint64 hash_query(const char* query);
static procEntry *ProcEntryArray = NULL;

/*
 * Module load callback
 */
void
_PG_init(void)
{
	/*
	 * In order to create our shared memory area, we have to be loaded via
	 * shared_preload_libraries.  If not, fall out without hooking into any of
	 * the main system.  (We don't throw error here because it seems useful to
	 * allow the pg_stat_sql_plans functions to be created even when the
	 * module isn't active.  The functions must protect themselves against
	 * being called then, however.)
	 */
	if (!process_shared_preload_libraries_in_progress)
		return;

	/*
	 * Define (or redefine) custom GUC variables.
	 */
	DefineCustomIntVariable("pg_stat_sql_plans.max",
							"Sets the maximum number of statements tracked by pg_stat_sql_plans.",
							NULL,
							&pgssp_max,
							5000,
							100,
							INT_MAX,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomEnumVariable("pg_stat_sql_plans.track",
							 "Selects which statements are tracked by pg_stat_sql_plans.",
							 NULL,
							 &pgssp_track,
							 pgssp_TRACK_TOP,
							 track_options,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_stat_sql_plans.track_utility",
							 "Selects whether utility commands are tracked by pg_stat_sql_plans.",
							 NULL,
							 &pgssp_track_utility,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);
	
	DefineCustomBoolVariable("pg_stat_sql_plans.track_errors",
							 "Selects whether statements in error are tracked by pg_stat_sql_plans.",
							 NULL,
							 &pgssp_track_errors,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

 	DefineCustomBoolVariable("pg_stat_sql_plans.track_planid",
							 "Selects whether Plans are tracked by pg_stat_sql_plans.",
							 NULL,
							 &pgssp_track_planid,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

 	DefineCustomBoolVariable("pg_stat_sql_plans.explain",
							 "Selects whether explain query by pg_stat_sql_plans.",
							 NULL,
							 &pgssp_explain,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_stat_sql_plans.save",
							 "Save pg_stat_sql_plans statistics across server shutdowns.",
							 NULL,
							 &pgssp_save,
							 true,
							 PGC_SIGHUP,
							 0,
							 NULL,
							 NULL,
							 NULL);

	EmitWarningsOnPlaceholders("pg_stat_sql_plans");

	/*
	 * Request additional shared resources.  (These are no-ops if we're not in
	 * the postmaster process.)  We'll allocate or attach to the shared
	 * resources in pgssp_shmem_startup().
	 */
	RequestAddinShmemSpace(pgssp_memsize());
	RequestNamedLWLockTranche("pg_stat_sql_plans", 1);

	/*
	 * Install hooks.
	 */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgssp_shmem_startup;
	prev_planner_hook = planner_hook;
    planner_hook = pgssp_planner;
	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = pgssp_post_parse_analyze;
	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pgssp_ExecutorStart;
	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = pgssp_ExecutorRun;
	prev_ExecutorFinish = ExecutorFinish_hook;
	ExecutorFinish_hook = pgssp_ExecutorFinish;
	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pgssp_ExecutorEnd;
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pgssp_ProcessUtility;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	shmem_startup_hook = prev_shmem_startup_hook;
	planner_hook = prev_planner_hook;
	post_parse_analyze_hook = prev_post_parse_analyze_hook;
	ExecutorStart_hook = prev_ExecutorStart;
	ExecutorRun_hook = prev_ExecutorRun;
	ExecutorFinish_hook = prev_ExecutorFinish;
	ExecutorEnd_hook = prev_ExecutorEnd;
	ProcessUtility_hook = prev_ProcessUtility;
}

/*
 * shmem_startup hook: allocate or attach to shared memory,
 * then load any pre-existing statistics from file.
 * Also create and load the query-texts file, which is expected to exist
 * (even if empty) while the module is enabled.
 */
static void
pgssp_shmem_startup(void)
{
	bool		found;
	HASHCTL		info;
	FILE	   *file = NULL;
	FILE	   *qfile = NULL;
	uint32		header;
	int32		num;
	int32		pgver;
	int32		i;
	int			buffer_size;
	char	   *buffer = NULL;
	int 		size;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* reset in case this is a restart within the postmaster */
	pgssp = NULL;
	pgssp_hash = NULL;

	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	/* spécific for ProcEntryArray */
	size = mul_size(sizeof(procEntry), get_max_procs_count());
	ProcEntryArray = (procEntry *) ShmemInitStruct("Proc Entry Array", size, &found);
	if (!found)
	{
		MemSet(ProcEntryArray, 0, size);
	}

	pgssp = ShmemInitStruct("pg_stat_sql_plans",
						   sizeof(pgsspSharedState),
						   &found);

	if (!found)
	{
		/* First time through ... */
		pgssp->lock = &(GetNamedLWLockTranche("pg_stat_sql_plans"))->lock;
		pgssp->cur_median_usage = ASSUMED_MEDIAN_INIT;
		pgssp->mean_query_len = ASSUMED_LENGTH_INIT;
		SpinLockInit(&pgssp->mutex);
		pgssp->extent = 0;
		pgssp->n_writers = 0;
		pgssp->gc_count = 0;
	}

	memset(&info, 0, sizeof(info));
	info.keysize = sizeof(pgsspHashKey);
	info.entrysize = sizeof(pgsspEntry);
	pgssp_hash = ShmemInitHash("pg_stat_sql_plans hash",
							  pgssp_max, pgssp_max,
							  &info,
							  HASH_ELEM | HASH_BLOBS);

	LWLockRelease(AddinShmemInitLock);

	/*
	 * If we're in the postmaster (or a standalone backend...), set up a shmem
	 * exit hook to dump the statistics to disk.
	 */
	if (!IsUnderPostmaster)
		on_shmem_exit(pgssp_shmem_shutdown, (Datum) 0);

	/*
	 * Done if some other process already completed our initialization.
	 */
	if (found)
		return;

	/*
	 * Note: we don't bother with locks here, because there should be no other
	 * processes running when this code is reached.
	 */

	/* Unlink query text file possibly left over from crash */
	unlink(pgssp_TEXT_FILE);

	/* Allocate new query text temp file */
	qfile = AllocateFile(pgssp_TEXT_FILE, PG_BINARY_W);
	if (qfile == NULL)
		goto write_error;

	/*
	 * If we were told not to load old statistics, we're done.  (Note we do
	 * not try to unlink any old dump file in this case.  This seems a bit
	 * questionable but it's the historical behavior.)
	 */
	if (!pgssp_save)
	{
		FreeFile(qfile);
		return;
	}

	/*
	 * Attempt to load old statistics from the dump file.
	 */
	file = AllocateFile(pgssp_DUMP_FILE, PG_BINARY_R);
	if (file == NULL)
	{
		if (errno != ENOENT)
			goto read_error;
		/* No existing persisted stats file, so we're done */
		FreeFile(qfile);
		return;
	}

	buffer_size = 2048;
	buffer = (char *) palloc(buffer_size);

	if (fread(&header, sizeof(uint32), 1, file) != 1 ||
		fread(&pgver, sizeof(uint32), 1, file) != 1 ||
		fread(&num, sizeof(int32), 1, file) != 1)
		goto read_error;

	if (header != pgssp_FILE_HEADER ||
		pgver != pgssp_PG_MAJOR_VERSION)
		goto data_error;

	for (i = 0; i < num; i++)
	{
		pgsspEntry	temp;
		pgsspEntry  *entry;
		Size		query_offset;

		if (fread(&temp, sizeof(pgsspEntry), 1, file) != 1)
			goto read_error;

		/* Encoding is the only field we can easily sanity-check */
		if (!PG_VALID_BE_ENCODING(temp.encoding))
			goto data_error;

		/* Resize buffer as needed */
		if (temp.query_len >= buffer_size)
		{
			buffer_size = Max(buffer_size * 2, temp.query_len + 1);
			buffer = repalloc(buffer, buffer_size);
		}

		if (fread(buffer, 1, temp.query_len + 1, file) != temp.query_len + 1)
			goto read_error;

		/* Should have a trailing null, but let's make sure */
		buffer[temp.query_len] = '\0';

		/* Skip loading "sticky" entries */
		if (temp.counters.calls == 0)
			continue;

		/* Store the query text */
		query_offset = pgssp->extent;
		if (fwrite(buffer, 1, temp.query_len + 1, qfile) != temp.query_len + 1)
			goto write_error;
		pgssp->extent += temp.query_len + 1;

		/* make the hashtable entry (discards old entries if too many) */
		entry = entry_alloc(&temp.key, query_offset, temp.query_len,
							temp.encoding);

		/* copy in the actual stats */
		entry->counters = temp.counters;
	}

	pfree(buffer);
	FreeFile(file);
	FreeFile(qfile);

	/*
	 * Remove the persisted stats file so it's not included in
	 * backups/replication slaves, etc.  A new file will be written on next
	 * shutdown.
	 *
	 * Note: it's okay if the pgssp_TEXT_FILE is included in a basebackup,
	 * because we remove that file on startup; it acts inversely to
	 * pgssp_DUMP_FILE, in that it is only supposed to be around when the
	 * server is running, whereas pgssp_DUMP_FILE is only supposed to be around
	 * when the server is not running.  Leaving the file creates no danger of
	 * a newly restored database having a spurious record of execution costs,
	 * which is what we're really concerned about here.
	 */
	unlink(pgssp_DUMP_FILE);

	return;

read_error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not read pg_stat_statement file \"%s\": %m",
					pgssp_DUMP_FILE)));
	goto fail;
data_error:
	ereport(LOG,
			(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
			 errmsg("ignoring invalid data in pg_stat_statement file \"%s\"",
					pgssp_DUMP_FILE)));
	goto fail;
write_error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not write pg_stat_statement file \"%s\": %m",
					pgssp_TEXT_FILE)));
fail:
	if (buffer)
		pfree(buffer);
	if (file)
		FreeFile(file);
	if (qfile)
		FreeFile(qfile);
	/* If possible, throw away the bogus file; ignore any error */
	unlink(pgssp_DUMP_FILE);

	/*
	 * Don't unlink pgssp_TEXT_FILE here; it should always be around while the
	 * server is running with pg_stat_sql_plans enabled
	 */
}

/*
 * shmem_shutdown hook: Dump statistics into file.
 *
 * Note: we don't bother with acquiring lock, because there should be no
 * other processes running when this is called.
 */
static void
pgssp_shmem_shutdown(int code, Datum arg)
{
	FILE	   *file;
	char	   *qbuffer = NULL;
	Size		qbuffer_size = 0;
	HASH_SEQ_STATUS hash_seq;
	int32		num_entries;
	pgsspEntry  *entry;

	/* Don't try to dump during a crash. */
	if (code)
		return;

	/* Safety check ... shouldn't get here unless shmem is set up. */
	if (!pgssp || !pgssp_hash)
		return;

	/* Don't dump if told not to. */
	if (!pgssp_save)
		return;

	file = AllocateFile(pgssp_DUMP_FILE ".tmp", PG_BINARY_W);
	if (file == NULL)
		goto error;

	if (fwrite(&pgssp_FILE_HEADER, sizeof(uint32), 1, file) != 1)
		goto error;
	if (fwrite(&pgssp_PG_MAJOR_VERSION, sizeof(uint32), 1, file) != 1)
		goto error;
	num_entries = hash_get_num_entries(pgssp_hash);
	if (fwrite(&num_entries, sizeof(int32), 1, file) != 1)
		goto error;

	qbuffer = qtext_load_file(&qbuffer_size);
	if (qbuffer == NULL)
		goto error;

	/*
	 * When serializing to disk, we store query texts immediately after their
	 * entry data.  Any orphaned query texts are thereby excluded.
	 */
	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		int			len = entry->query_len;
		char	   *qstr = qtext_fetch(entry->query_offset, len,
									   qbuffer, qbuffer_size);

		if (qstr == NULL)
			qstr = "";
			

		if (fwrite(entry, sizeof(pgsspEntry), 1, file) != 1 ||
			fwrite(qstr, 1, len + 1, file) != len + 1)
		{
			/* note: we assume hash_seq_term won't change errno */
			hash_seq_term(&hash_seq);
			goto error;
		}
	}

	free(qbuffer);
	qbuffer = NULL;

	if (FreeFile(file))
	{
		file = NULL;
		goto error;
	}

	/*
	 * Rename file into place, so we atomically replace any old one.
	 */
	(void) durable_rename(pgssp_DUMP_FILE ".tmp", pgssp_DUMP_FILE, LOG);

	/* Unlink query-texts file; it's not needed while shutdown */
	unlink(pgssp_TEXT_FILE);

	return;

error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not write pg_stat_statement file \"%s\": %m",
					pgssp_DUMP_FILE ".tmp")));
	if (qbuffer)
		free(qbuffer);
	if (file)
		FreeFile(file);
	unlink(pgssp_DUMP_FILE ".tmp");
	unlink(pgssp_TEXT_FILE);
}

/*
 * Calculate max processes count.
 */
static int
get_max_procs_count(void)
{
	int count = 0;

	/* MyProcs, including autovacuum workers and launcher */
	count += MaxBackends;
	/* AuxiliaryProcs */
	count += NUM_AUXILIARY_PROCS;
	/* Prepared xacts */
	count += max_prepared_xacts;

	return count;
}

/*
 * Post-parse-analysis hook: mark query with a queryId
 */
static void
pgssp_post_parse_analyze(ParseState *pstate, Query *query)
{
	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query);

	/* Assert we didn't do this already */
	Assert(query->queryId == UINT64CONST(0));

	/* Safety check... */
	if (!pgssp || !pgssp_hash)
		return;

	/* Update memory structure dedicated for pgssp_backend_queryid function */
	if (MyProc)
	{
		int i = MyProc - ProcGlobal->allProcs;
		const char *querytext = pstate->p_sourcetext;
		int query_len;
		int query_location = query->stmt_location;
		query_len = query->stmt_len;

		if (query_location >= 0)
		{
			Assert(query_location <= strlen(querytext));
			querytext += query_location;
			/* Length of 0 (or -1) means "rest of string" */
			if (query_len <= 0)
				query_len = strlen(querytext);
			else
				Assert(query_len <= strlen(querytext));
		}
		else
		{
			/* If query location is unknown, distrust query_len as well */
			query_location = 0;
			query_len = strlen(querytext);
		}

		/*
		 * Discard leading and trailing whitespace, too.  Use scanner_isspace()
		 * not libc's isspace(), because we want to match the lexer's behavior.
		 */
		while (query_len > 0 && scanner_isspace(querytext[0]))
			querytext++, query_location++, query_len--;
		while (query_len > 0 && scanner_isspace(querytext[query_len - 1]))
			query_len--;
		
		/* store queryid, hash query or utility statement text */
		if (query->utilityStmt) {
			ProcEntryArray[i].queryid =  pgssp_hash_string(querytext, query_len);
		} else {
			ProcEntryArray[i].queryid =  hash_query(pstate->p_sourcetext);
		}
	}

	/*
	 * Utility statements get queryId zero.  We do this even in cases where
	 * the statement contains an optimizable statement for which a queryId
	 * could be derived (such as EXPLAIN or DECLARE CURSOR).  For such cases,
	 * runtime control will first go through ProcessUtility and then the
	 * executor, and we don't want the executor hooks to do anything, since we
	 * are already measuring the statement's costs at the utility level.
	 */
	if (query->utilityStmt)
	{
		query->queryId = UINT64CONST(0);
		return;
	}

	/* Compute query ID and mark the Query node with it */
	query->queryId = hash_query(pstate->p_sourcetext);

	/*
	 * If we are unlucky enough to get a hash of zero, use 1 instead, to
	 * prevent confusion with the utility-statement case.
	 */
	if (query->queryId == UINT64CONST(0))
		query->queryId = UINT64CONST(1);

}

  /*
  * planner hook
  */

 static PlannedStmt *
 pgssp_planner(Query *parse, int cursorOptions, ParamListInfo boundParams)
 {
 	PlannedStmt *result;

	if (pgssp_enabled())
 	{
		instr_time		start;
		instr_time		duration;
		BufferUsage 	bufusage;

		INSTR_TIME_SET_CURRENT(start);
		
		//		pgstat_report_wait_start(0x0B010000U); // gives ???-unknown wait event
	 	pgstat_report_wait_start(0x050E0000U); // gives Activity-unknown wait event

 
		nested_level++;
 		PG_TRY();
 		{
 			if (prev_planner_hook)
 				result = prev_planner_hook(parse, cursorOptions, boundParams);
 			else
 				result = standard_planner(parse, cursorOptions, boundParams);
 			nested_level--;
 		}
 		PG_CATCH();
 		{
 			nested_level--;
 			PG_RE_THROW();
 		}
 		PG_END_TRY();
 
 		INSTR_TIME_SET_CURRENT(duration);
		INSTR_TIME_SUBTRACT(duration, start);
 		
		bufusage.shared_blks_hit = 0;
		bufusage.shared_blks_read = 0;
		bufusage.shared_blks_dirtied = 0;
		bufusage.shared_blks_written = 0;
		bufusage.local_blks_hit = 0;
		bufusage.local_blks_read = 0;
		bufusage.local_blks_dirtied = 0;
		bufusage.local_blks_written = 0;
		bufusage.temp_blks_read = 0;
		bufusage.temp_blks_written = 0;
//?? à voir
//		INSTR_TIME_SUBTRACT(bufusage.blk_read_time, bufusage.blk_read_time);
//		INSTR_TIME_SUBTRACT(bufusage.blk_write_time, bufusage.blk_write_time);
		pgssp_store(    "",
						parse->queryId,
						NULL,
					    0,
					    0,
					   INSTR_TIME_GET_MILLISEC(duration),
					   0, 	/* rows */ 
					   &bufusage);
					   
		pgstat_report_wait_end();
 	}
 	else
 	{
 		if (prev_planner_hook)
 			result = prev_planner_hook(parse, cursorOptions, boundParams);
 		else
 			result = standard_planner(parse, cursorOptions, boundParams);
 	}

 	return result;
 }

/*
 * ExecutorStart hook: start up tracking if needed
 */
static void
pgssp_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	/*
	 * If query has queryId zero, don't track it.  This prevents double
	 * counting of optimizable statements that are directly contained in
	 * utility statements.
	 */
	if (pgssp_enabled() && queryDesc->plannedstmt->queryId != UINT64CONST(0))
	{
		/*
		 * Set up to track total elapsed time in ExecutorRun.  Make sure the
		 * space is allocated in the per-query context so it will go away at
		 * ExecutorEnd.
		 */
		if (queryDesc->totaltime == NULL)
		{
			MemoryContext oldcxt;

			oldcxt = MemoryContextSwitchTo(queryDesc->estate->es_query_cxt);
			queryDesc->totaltime = InstrAlloc(1, INSTRUMENT_ALL);
			MemoryContextSwitchTo(oldcxt);
		}
	}
}

/*
 * ExecutorRun hook: all we need do is track nesting depth
 */
static void
pgssp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count,
				 bool execute_once)
{
	nested_level++;
	PG_TRY();
	{
		if (prev_ExecutorRun)
			prev_ExecutorRun(queryDesc, direction, count, execute_once);
		else
			standard_ExecutorRun(queryDesc, direction, count, execute_once);
		nested_level--;
	}
	PG_CATCH();
	{
       	if (queryDesc->totaltime && pgssp_enabled() && pgssp_track_errors)
		{
			/* Part to get counters on errors */
			EState       *estate;
           	estate = queryDesc->estate;
           	InstrStopNode(queryDesc->totaltime, estate->es_processed);
           	InstrEndLoop(queryDesc->totaltime);

			pgssp_store(queryDesc->sourceText,
			   queryDesc->plannedstmt->queryId,
			   queryDesc,
			   queryDesc->plannedstmt->stmt_location,
			   queryDesc->plannedstmt->stmt_len,
			   queryDesc->totaltime->total * 1000.0,	/* convert to msec */
			   queryDesc->estate->es_processed,
			   &queryDesc->totaltime->bufusage);
		}
		nested_level--;
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * ExecutorFinish hook: all we need do is track nesting depth
 */
static void
pgssp_ExecutorFinish(QueryDesc *queryDesc)
{
	nested_level++;
	PG_TRY();
	{
		if (prev_ExecutorFinish)
			prev_ExecutorFinish(queryDesc);
		else
			standard_ExecutorFinish(queryDesc);
		nested_level--;
	}
	PG_CATCH();
	{
		nested_level--;
		PG_RE_THROW();
	}
	PG_END_TRY();
}

/*
 * ExecutorEnd hook: store results if needed
 */
static void
pgssp_ExecutorEnd(QueryDesc *queryDesc)
{
	uint64		queryId = queryDesc->plannedstmt->queryId;

	if (queryId != UINT64CONST(0) && queryDesc->totaltime && pgssp_enabled())
	{
		/*
		 * Make sure stats accumulation is done.  (Note: it's okay if several
		 * levels of hook all do this.)
		 */

		InstrEndLoop(queryDesc->totaltime);

		pgssp_store(queryDesc->sourceText,
				   queryId,
				   queryDesc,
				   queryDesc->plannedstmt->stmt_location,
				   queryDesc->plannedstmt->stmt_len,
				   queryDesc->totaltime->total * 1000.0,	/* convert to msec */
				   queryDesc->estate->es_processed,
				   &queryDesc->totaltime->bufusage);
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * ProcessUtility hook
 */
static void
pgssp_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params, QueryEnvironment *queryEnv,
					DestReceiver *dest, char *completionTag)
{
	Node	   *parsetree = pstmt->utilityStmt;

	/*
	 * If it's an EXECUTE statement, we don't track it and don't increment the
	 * nesting level.  This allows the cycles to be charged to the underlying
	 * PREPARE instead (by the Executor hooks), which is much more useful.
	 *
	 * We also don't track execution of PREPARE.  If we did, we would get one
	 * hash table entry for the PREPARE (with hash calculated from the query
	 * string), and then a different one with the same query string (but hash
	 * calculated from the query tree) would be used to accumulate costs of
	 * ensuing EXECUTEs.  This would be confusing, and inconsistent with other
	 * cases where planning time is not included at all.
	 *
	 * Likewise, we don't track execution of DEALLOCATE.
	 */
	if (pgssp_track_utility && pgssp_enabled() &&
		!IsA(parsetree, ExecuteStmt) &&
		!IsA(parsetree, PrepareStmt) &&
		!IsA(parsetree, DeallocateStmt))
	{
		instr_time	start;
		instr_time	duration;
		uint64		rows;
		BufferUsage bufusage_start,
					bufusage;

		bufusage_start = pgBufferUsage;
		INSTR_TIME_SET_CURRENT(start);

		nested_level++;
		PG_TRY();
		{
			if (prev_ProcessUtility)
				prev_ProcessUtility(pstmt, queryString,
									context, params, queryEnv,
									dest, completionTag);
			else
				standard_ProcessUtility(pstmt, queryString,
										context, params, queryEnv,
										dest, completionTag);
			nested_level--;
		}
		PG_CATCH();
		{
			if(pgssp_track_errors)
			{
				/* Part to get counters on errors */
				INSTR_TIME_SET_CURRENT(duration);
				INSTR_TIME_SUBTRACT(duration, start);

				/* calc differences of buffer counters. */
				bufusage.shared_blks_hit =
					pgBufferUsage.shared_blks_hit - bufusage_start.shared_blks_hit;
				bufusage.shared_blks_read =
					pgBufferUsage.shared_blks_read - bufusage_start.shared_blks_read;
				bufusage.shared_blks_dirtied =
					pgBufferUsage.shared_blks_dirtied - bufusage_start.shared_blks_dirtied;
				bufusage.shared_blks_written =
					pgBufferUsage.shared_blks_written - bufusage_start.shared_blks_written;
				bufusage.local_blks_hit =
					pgBufferUsage.local_blks_hit - bufusage_start.local_blks_hit;
				bufusage.local_blks_read =
					pgBufferUsage.local_blks_read - bufusage_start.local_blks_read;
				bufusage.local_blks_dirtied =
					pgBufferUsage.local_blks_dirtied - bufusage_start.local_blks_dirtied;
				bufusage.local_blks_written =
					pgBufferUsage.local_blks_written - bufusage_start.local_blks_written;
				bufusage.temp_blks_read =
					pgBufferUsage.temp_blks_read - bufusage_start.temp_blks_read;
				bufusage.temp_blks_written =
					pgBufferUsage.temp_blks_written - bufusage_start.temp_blks_written;
				bufusage.blk_read_time = pgBufferUsage.blk_read_time;
				INSTR_TIME_SUBTRACT(bufusage.blk_read_time, bufusage_start.blk_read_time);
				bufusage.blk_write_time = pgBufferUsage.blk_write_time;
				INSTR_TIME_SUBTRACT(bufusage.blk_write_time, bufusage_start.blk_write_time);

			pgssp_store(queryString,
					   0,	/* signal that it's a utility stmt */
						NULL,
					   pstmt->stmt_location,
					   pstmt->stmt_len,
					   INSTR_TIME_GET_MILLISEC(duration),
					   0, 	/* rows */ 
					   &bufusage);
			};
			nested_level--;
			PG_RE_THROW();
		}
		PG_END_TRY();

		INSTR_TIME_SET_CURRENT(duration);
		INSTR_TIME_SUBTRACT(duration, start);

		/* parse command tag to retrieve the number of affected rows. */
		if (completionTag &&
			strncmp(completionTag, "COPY ", 5) == 0)
			rows = pg_strtouint64(completionTag + 5, NULL, 10);
		else
			rows = 0;

		/* calc differences of buffer counters. */
		bufusage.shared_blks_hit =
			pgBufferUsage.shared_blks_hit - bufusage_start.shared_blks_hit;
		bufusage.shared_blks_read =
			pgBufferUsage.shared_blks_read - bufusage_start.shared_blks_read;
		bufusage.shared_blks_dirtied =
			pgBufferUsage.shared_blks_dirtied - bufusage_start.shared_blks_dirtied;
		bufusage.shared_blks_written =
			pgBufferUsage.shared_blks_written - bufusage_start.shared_blks_written;
		bufusage.local_blks_hit =
			pgBufferUsage.local_blks_hit - bufusage_start.local_blks_hit;
		bufusage.local_blks_read =
			pgBufferUsage.local_blks_read - bufusage_start.local_blks_read;
		bufusage.local_blks_dirtied =
			pgBufferUsage.local_blks_dirtied - bufusage_start.local_blks_dirtied;
		bufusage.local_blks_written =
			pgBufferUsage.local_blks_written - bufusage_start.local_blks_written;
		bufusage.temp_blks_read =
			pgBufferUsage.temp_blks_read - bufusage_start.temp_blks_read;
		bufusage.temp_blks_written =
			pgBufferUsage.temp_blks_written - bufusage_start.temp_blks_written;
		bufusage.blk_read_time = pgBufferUsage.blk_read_time;
		INSTR_TIME_SUBTRACT(bufusage.blk_read_time, bufusage_start.blk_read_time);
		bufusage.blk_write_time = pgBufferUsage.blk_write_time;
		INSTR_TIME_SUBTRACT(bufusage.blk_write_time, bufusage_start.blk_write_time);

		pgssp_store(queryString,
				   0,			/* signal that it's a utility stmt */
				   NULL,
				   pstmt->stmt_location,
				   pstmt->stmt_len,
				   INSTR_TIME_GET_MILLISEC(duration),
				   rows,
				   &bufusage);
	}
	else
	{
		if (prev_ProcessUtility)
			prev_ProcessUtility(pstmt, queryString,
								context, params, queryEnv,
								dest, completionTag);
		else
			standard_ProcessUtility(pstmt, queryString,
									context, params, queryEnv,
									dest, completionTag);
	}
}

/*
 * Given an arbitrarily long query string, produce a hash for the purposes of
 * identifying the query, without normalizing constants.  Used when hashing
 * utility statements.
 */
static uint64
pgssp_hash_string(const char *str, int len)
{
	return DatumGetUInt64(hash_any_extended((const unsigned char *) str,
											len, 0));
}

/*
 * Store some statistics for a statement.
 *
 * If queryId is 0 then this is a utility statement and we should compute
 * a suitable queryId internally.
 *
 */
static void
pgssp_store(const char *query, uint64 queryId, QueryDesc *queryDesc,
		   int query_location, int query_len,
		   double total_time, uint64 rows,
		   const BufferUsage *bufusage)
{
	pgsspHashKey key;
	pgsspEntry  *entry;
	int			encoding = GetDatabaseEncoding();
	instr_time	start;
	instr_time	duration;
	ExplainState *es = NewExplainState();
	uint64 planId;
	INSTR_TIME_SET_CURRENT(start);
	pgstat_report_wait_start(PG_WAIT_EXTENSION);

	Assert(query != NULL);

	/* Safety check... */
	if (!pgssp || !pgssp_hash)
		return;

	/*
	 * Confine our attention to the relevant part of the string, if the query
	 * is a portion of a multi-statement source string.
	 *
	 * First apply starting offset, unless it's -1 (unknown).
	 */
	if (query_location >= 0)
	{
		Assert(query_location <= strlen(query));
		query += query_location;
		/* Length of 0 (or -1) means "rest of string" */
		if (query_len <= 0)
			query_len = strlen(query);
		else
			Assert(query_len <= strlen(query));
	}
	else
	{
		/* If query location is unknown, distrust query_len as well */
		query_location = 0;
		query_len = strlen(query);
	}

	/*
	 * Discard leading and trailing whitespace, too.  Use scanner_isspace()
	 * not libc's isspace(), because we want to match the lexer's behavior.
	 */
	while (query_len > 0 && scanner_isspace(query[0]))
		query++, query_location++, query_len--;
	while (query_len > 0 && scanner_isspace(query[query_len - 1]))
		query_len--;

	/*
	 * For utility statements, we just hash the query string to get an ID.
	 */
	if (queryId == UINT64CONST(0))
	{
		queryId = pgssp_hash_string(query, query_len);
		planId = UINT64CONST(0);
	}
	else
	{
		/* Build planid */
		if (pgssp_track_planid && query_len > 0)
		{
			/* this part comes from auto_explain, to be implemented later */

//			es->analyze = (queryDesc->instrument_options && auto_explain_log_analyze);
//			es->verbose = auto_explain_log_verbose;
//			es->buffers = (es->analyze && auto_explain_log_buffers);
//			es->timing = (es->analyze && auto_explain_log_timing);
//			es->summary = es->analyze;
//			es->format = auto_explain_log_format;
//			es->gucs = true;
			es->format = EXPLAIN_FORMAT_TEXT;

			ExplainBeginOutput(es);

//			ExplainQueryText(es, queryDesc);
			ExplainPrintPlan(es, queryDesc);
//			if (es->analyze && auto_explain_log_triggers)
//				ExplainPrintTriggers(es, queryDesc);
			ExplainEndOutput(es);

			/* Remove last line break */
			if (es->str->len > 0 && es->str->data[es->str->len - 1] == '\n')
				es->str->data[--es->str->len] = '\0';

			/* Fix JSON to output an object */
//			if (auto_explain_log_format == EXPLAIN_FORMAT_JSON)
//			{
//				es->str->data[0] = '{';
//				es->str->data[es->str->len - 1] = '}';
//			}

			planId = hash_query(es->str->data);
		}
		else
			if (query_len == 0)
				planId = UINT64CONST(-1);
			else	
				planId = UINT64CONST(1);
    }	
	/* Set up key for hashtable search */
	key.userid = GetUserId();
	key.dbid = MyDatabaseId;
	key.queryid = queryId;
	key.planid = planId;

	/* Lookup the hash table entry with shared lock. */
	LWLockAcquire(pgssp->lock, LW_SHARED);

	entry = (pgsspEntry *) hash_search(pgssp_hash, &key, HASH_FIND, NULL);

	/* Create new entry, at the end of execution*/
	if (!entry && planId != UINT64CONST(-1))
	{
		Size		query_offset;
		int			gc_count;
		bool		stored;
		bool		do_gc;


		/* Append new query text to file with only shared lock held */
		stored = qtext_store( query, query_len,
							 &query_offset, &gc_count);

		/*
		 * Determine whether we need to garbage collect external query texts
		 * while the shared lock is still held.  This micro-optimization
		 * avoids taking the time to decide this while holding exclusive lock.
		 */
		do_gc = need_gc_qtexts();

		/* Need exclusive lock to make a new hashtable entry - promote */
		LWLockRelease(pgssp->lock);
		LWLockAcquire(pgssp->lock, LW_EXCLUSIVE);

		/*
		 * A garbage collection may have occurred while we weren't holding the
		 * lock.  In the unlikely event that this happens, the query text we
		 * stored above will have been garbage collected, so write it again.
		 * This should be infrequent enough that doing it while holding
		 * exclusive lock isn't a performance problem.
		 */
		if (!stored || pgssp->gc_count != gc_count)
			stored = qtext_store( query, query_len,
								 &query_offset, NULL);

		/* If we failed to write to the text file, give up */
		if (!stored)
			goto done;

		/* OK to create a new hashtable entry */
		entry = entry_alloc(&key, query_offset, query_len, encoding);

		/* If needed, perform garbage collection while exclusive lock held */
		if (do_gc)
			gc_qtexts();

		if (planId != UINT64CONST(0) && planId != UINT64CONST(1) && pgssp_explain)
		{
			/*
			 * Plan is only logged one time for each queryid / planId
			 */
			ereport(LOG,
					(errmsg("queryid: %lld planid: %lld plan:\n%s",
							(long long)queryId, (long long)planId, es->str->data),
					 errhidecontext(true), errhidestmt(true)));
		}
	}

	/* add new entry after planning (without text) */ 
	if (!entry && planId == UINT64CONST(-1) )
	{
		LWLockRelease(pgssp->lock);
		LWLockAcquire(pgssp->lock, LW_EXCLUSIVE);
		/* OK to create a new hashtable entry  without text */
		entry = entry_alloc(&key, 0, 0, encoding);
	}
	
	/* Increment the counts */
	if (true)
	{
		/*
		 * Grab the spinlock while updating the counters (see comment about
		 * locking rules at the head of the file)
		 */
		volatile pgsspEntry *e = (volatile pgsspEntry *) entry;

		SpinLockAcquire(&e->mutex);

		/* "Unstick" entry if it was previously sticky */
		if (e->counters.calls == 0)
		{
			e->counters.first_call = GetCurrentTimestamp();
		}


		/* add pgssp_store function duration to total_time */
		// should by outside SpinLockAcquire
		INSTR_TIME_SET_CURRENT(duration);
		INSTR_TIME_SUBTRACT(duration, start);

		if(planId != UINT64CONST(-1))
			e->counters.exec_time += total_time; 
		else
			e->counters.plan_time += total_time; 
		
		e->counters.pgssp_time += INSTR_TIME_GET_MILLISEC(duration);
		total_time = total_time + INSTR_TIME_GET_MILLISEC(duration);
		
		e->counters.calls += 1;
		e->counters.total_time += total_time ;
		if (e->counters.calls == 1)
		{
			e->counters.min_time = total_time;
			e->counters.max_time = total_time;
			e->counters.mean_time = total_time;
		}
		else
		{
			/*
			 * Welford's method for accurately computing variance. See
			 * <http://www.johndcook.com/blog/standard_deviation/>
			 */
			double		old_mean = e->counters.mean_time;

			e->counters.mean_time +=
				(total_time - old_mean) / e->counters.calls;
			e->counters.sum_var_time +=
				(total_time - old_mean) * (total_time - e->counters.mean_time);

			/* calculate min and max time */
			if (e->counters.min_time > total_time)
				e->counters.min_time = total_time;
			if (e->counters.max_time < total_time)
				e->counters.max_time = total_time;
		}
		e->counters.rows += rows;
		e->counters.shared_blks_hit += bufusage->shared_blks_hit;
		e->counters.shared_blks_read += bufusage->shared_blks_read;
		e->counters.shared_blks_dirtied += bufusage->shared_blks_dirtied;
		e->counters.shared_blks_written += bufusage->shared_blks_written;
		e->counters.local_blks_hit += bufusage->local_blks_hit;
		e->counters.local_blks_read += bufusage->local_blks_read;
		e->counters.local_blks_dirtied += bufusage->local_blks_dirtied;
		e->counters.local_blks_written += bufusage->local_blks_written;
		e->counters.temp_blks_read += bufusage->temp_blks_read;
		e->counters.temp_blks_written += bufusage->temp_blks_written;
		e->counters.blk_read_time += INSTR_TIME_GET_MILLISEC(bufusage->blk_read_time);
		e->counters.blk_write_time += INSTR_TIME_GET_MILLISEC(bufusage->blk_write_time);
		e->counters.last_call = GetCurrentTimestamp();

		SpinLockRelease(&e->mutex);
	}

done:
	LWLockRelease(pgssp->lock);

	pgstat_report_wait_end();
}

/*
 * Reset all statement statistics.
 */
Datum
pg_stat_sql_plans_reset(PG_FUNCTION_ARGS)
{
	if (!pgssp || !pgssp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_stat_sql_plans must be loaded via shared_preload_libraries")));
	entry_reset();
	PG_RETURN_VOID();
}

/* Number of output arguments (columns) for various API versions */
#define pg_stat_sql_plans_COLS_V1_0	14
#define pg_stat_sql_plans_COLS_V1_1	18
#define pg_stat_sql_plans_COLS_V1_2	19
#define pg_stat_sql_plans_COLS_V1_3	29
#define pg_stat_sql_plans_COLS			29	/* maximum of above */

/*
 * Retrieve statement statistics.
 *
 * The SQL API of this function has changed multiple times, and will likely
 * do so again in future.  To support the case where a newer version of this
 * loadable module is being used with an old SQL declaration of the function,
 * we continue to support the older API versions.  For 1.2 and later, the
 * expected API version is identified by embedding it in the C name of the
 * function.  Unfortunately we weren't bright enough to do that for 1.1.
 */
Datum
pg_stat_sql_plans_1_3(PG_FUNCTION_ARGS)
{
	bool		showtext = PG_GETARG_BOOL(0);

	pg_stat_sql_plans_internal(fcinfo, pgssp_V1_3, showtext);

	return (Datum) 0;
}

Datum
pg_stat_sql_plans_1_2(PG_FUNCTION_ARGS)
{
	bool		showtext = PG_GETARG_BOOL(0);

	pg_stat_sql_plans_internal(fcinfo, pgssp_V1_2, showtext);

	return (Datum) 0;
}

/*
 * Legacy entry point for pg_stat_sql_plans() API versions 1.0 and 1.1.
 * This can be removed someday, perhaps.
 */
Datum
pg_stat_sql_plans(PG_FUNCTION_ARGS)
{
	/* If it's really API 1.1, we'll figure that out below */
	pg_stat_sql_plans_internal(fcinfo, pgssp_V1_0, true);

	return (Datum) 0;
}

/* Common code for all versions of pg_stat_sql_plans() */
static void
pg_stat_sql_plans_internal(FunctionCallInfo fcinfo,
							pgsspVersion api_version,
							bool showtext)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc	tupdesc;
	Tuplestorestate *tupstore;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	Oid			userid = GetUserId();
	bool		is_allowed_role = false;
	char	   *qbuffer = NULL;
	Size		qbuffer_size = 0;
	Size		extent = 0;
	int			gc_count = 0;
	HASH_SEQ_STATUS hash_seq;
	pgsspEntry  *entry;

	/* Superusers or members of pg_read_all_stats members are allowed */
    is_allowed_role = is_member_of_role(GetUserId(), DEFAULT_ROLE_READ_ALL_STATS);

	/* hash table must exist already */
	if (!pgssp || !pgssp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_stat_sql_plans must be loaded via shared_preload_libraries")));

	/* check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Switch into long-lived context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	/*
	 * Check we have the expected number of output arguments.  Aside from
	 * being a good safety check, we need a kluge here to detect API version
	 * 1.1, which was wedged into the code in an ill-considered way.
	 */
	switch (tupdesc->natts)
	{
		case pg_stat_sql_plans_COLS_V1_0:
			if (api_version != pgssp_V1_0)
				elog(ERROR, "incorrect number of output arguments");
			break;
		case pg_stat_sql_plans_COLS_V1_1:
			/* pg_stat_sql_plans() should have told us 1.0 */
			if (api_version != pgssp_V1_0)
				elog(ERROR, "incorrect number of output arguments");
			api_version = pgssp_V1_1;
			break;
		case pg_stat_sql_plans_COLS_V1_2:
			if (api_version != pgssp_V1_2)
				elog(ERROR, "incorrect number of output arguments");
			break;
		case pg_stat_sql_plans_COLS_V1_3:
			if (api_version != pgssp_V1_3)
				elog(ERROR, "incorrect number of output arguments");
			break;
		default:
			elog(ERROR, "incorrect number of output arguments");
	}

	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	MemoryContextSwitchTo(oldcontext);

	/*
	 * We'd like to load the query text file (if needed) while not holding any
	 * lock on pgssp->lock.  In the worst case we'll have to do this again
	 * after we have the lock, but it's unlikely enough to make this a win
	 * despite occasional duplicated work.  We need to reload if anybody
	 * writes to the file (either a retail qtext_store(), or a garbage
	 * collection) between this point and where we've gotten shared lock.  If
	 * a qtext_store is actually in progress when we look, we might as well
	 * skip the speculative load entirely.
	 */
	if (showtext)
	{
		int			n_writers;

		/* Take the mutex so we can examine variables */
		{
			volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp;

			SpinLockAcquire(&s->mutex);
			extent = s->extent;
			n_writers = s->n_writers;
			gc_count = s->gc_count;
			SpinLockRelease(&s->mutex);
		}

		/* No point in loading file now if there are active writers */
		if (n_writers == 0)
			qbuffer = qtext_load_file(&qbuffer_size);
	}

	/*
	 * Get shared lock, load or reload the query text file if we must, and
	 * iterate over the hashtable entries.
	 *
	 * With a large hash table, we might be holding the lock rather longer
	 * than one could wish.  However, this only blocks creation of new hash
	 * table entries, and the larger the hash table the less likely that is to
	 * be needed.  So we can hope this is okay.  Perhaps someday we'll decide
	 * we need to partition the hash table to limit the time spent holding any
	 * one lock.
	 */
	LWLockAcquire(pgssp->lock, LW_SHARED);

	if (showtext)
	{
		/*
		 * Here it is safe to examine extent and gc_count without taking the
		 * mutex.  Note that although other processes might change
		 * pgssp->extent just after we look at it, the strings they then write
		 * into the file cannot yet be referenced in the hashtable, so we
		 * don't care whether we see them or not.
		 *
		 * If qtext_load_file fails, we just press on; we'll return NULL for
		 * every query text.
		 */
		if (qbuffer == NULL ||
			pgssp->extent != extent ||
			pgssp->gc_count != gc_count)
		{
			if (qbuffer)
				free(qbuffer);
			qbuffer = qtext_load_file(&qbuffer_size);
		}
	}

	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		Datum		values[pg_stat_sql_plans_COLS];
		bool		nulls[pg_stat_sql_plans_COLS];
		int			i = 0;
		Counters	tmp;
		double		stddev;
		int64		queryid = entry->key.queryid;
		int64		planid = entry->key.planid;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		values[i++] = ObjectIdGetDatum(entry->key.userid);
		values[i++] = ObjectIdGetDatum(entry->key.dbid);

		if (is_allowed_role || entry->key.userid == userid)
		{
			if (api_version >= pgssp_V1_2)
				values[i++] = Int64GetDatumFast(queryid);

			if (api_version >= pgssp_V1_3)
				values[i++] = Int64GetDatumFast(planid);

			if (showtext)
			{
				char	   *qstr = qtext_fetch(entry->query_offset,
											   entry->query_len,
											   qbuffer,
											   qbuffer_size);

				if (qstr)
				{
					char	   *enc;

					enc = pg_any_to_server(qstr,
										   entry->query_len,
										   entry->encoding);

					values[i++] = CStringGetTextDatum(enc);

					if (enc != qstr)
						pfree(enc);
				}
				else
				{
					/* Just return a null if we fail to find the text */
					nulls[i++] = true;
				}
			}
			else
			{
				/* Query text not requested */
				nulls[i++] = true;
			}
		}
		else
		{
			/* Don't show queryid */
			if (api_version >= pgssp_V1_2)
				nulls[i++] = true;

			/*
			 * Don't show query text, but hint as to the reason for not doing
			 * so if it was requested
			 */
			if (showtext)
				values[i++] = CStringGetTextDatum("<insufficient privilege>");
			else
				nulls[i++] = true;
		}

		/* copy counters to a local variable to keep locking time short */
		{
			volatile pgsspEntry *e = (volatile pgsspEntry *) entry;

			SpinLockAcquire(&e->mutex);
			tmp = e->counters;
			SpinLockRelease(&e->mutex);
		}

		/* Skip entry if unexecuted (ie, it's a pending "sticky" entry) */
		if (tmp.calls == 0)
			continue;

		values[i++] = Int64GetDatumFast(tmp.calls);
		values[i++] = Float8GetDatumFast(tmp.total_time);
		if (api_version >= pgssp_V1_3)
		{
			values[i++] = Float8GetDatumFast(tmp.min_time);
			values[i++] = Float8GetDatumFast(tmp.max_time);
			values[i++] = Float8GetDatumFast(tmp.mean_time);

			/*
			 * Note we are calculating the population variance here, not the
			 * sample variance, as we have data for the whole population, so
			 * Bessel's correction is not used, and we don't divide by
			 * tmp.calls - 1.
			 */
			if (tmp.calls > 1)
				stddev = sqrt(tmp.sum_var_time / tmp.calls);
			else
				stddev = 0.0;
			values[i++] = Float8GetDatumFast(stddev);
			values[i++] = Float8GetDatumFast(tmp.plan_time);
			values[i++] = Float8GetDatumFast(tmp.exec_time);
			values[i++] = Float8GetDatumFast(tmp.pgssp_time);
		}
		values[i++] = Int64GetDatumFast(tmp.rows);
		values[i++] = Int64GetDatumFast(tmp.shared_blks_hit);
		values[i++] = Int64GetDatumFast(tmp.shared_blks_read);
		if (api_version >= pgssp_V1_1)
			values[i++] = Int64GetDatumFast(tmp.shared_blks_dirtied);
		values[i++] = Int64GetDatumFast(tmp.shared_blks_written);
		values[i++] = Int64GetDatumFast(tmp.local_blks_hit);
		values[i++] = Int64GetDatumFast(tmp.local_blks_read);
		if (api_version >= pgssp_V1_1)
			values[i++] = Int64GetDatumFast(tmp.local_blks_dirtied);
		values[i++] = Int64GetDatumFast(tmp.local_blks_written);
		values[i++] = Int64GetDatumFast(tmp.temp_blks_read);
		values[i++] = Int64GetDatumFast(tmp.temp_blks_written);
		if (api_version >= pgssp_V1_1)
		{
			values[i++] = Float8GetDatumFast(tmp.blk_read_time);
			values[i++] = Float8GetDatumFast(tmp.blk_write_time);
		}
		values[i++] = TimestampTzGetDatum(tmp.first_call);
		values[i++] = TimestampTzGetDatum(tmp.last_call);

		Assert(i == (api_version == pgssp_V1_0 ? pg_stat_sql_plans_COLS_V1_0 :
					 api_version == pgssp_V1_1 ? pg_stat_sql_plans_COLS_V1_1 :
					 api_version == pgssp_V1_2 ? pg_stat_sql_plans_COLS_V1_2 :
					 api_version == pgssp_V1_3 ? pg_stat_sql_plans_COLS_V1_3 :
					 -1 /* fail if you forget to update this assert */ ));

		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}

	/* clean up and return the tuplestore */
	LWLockRelease(pgssp->lock);

	if (qbuffer)
		free(qbuffer);

	tuplestore_donestoring(tupstore);
}

/*
 * Estimate shared memory space needed.
 */
static Size
pgssp_memsize(void)
{
	Size		size;

	size = MAXALIGN(sizeof(pgsspSharedState));
	size = add_size(size, hash_estimate_size(pgssp_max, sizeof(pgsspEntry)));

	return size;
}

/*
 * Allocate a new hashtable entry.
 * caller must hold an exclusive lock on pgssp->lock
 *
 * "query" need not be null-terminated; we rely on query_len instead
 *
 * If "sticky" is true, make the new entry artificially sticky so that it will
 * probably still be there when the query finishes execution.  We do this by
 * giving it a median usage value rather than the normal value.  (Strictly
 * speaking, query strings are normalized on a best effort basis, though it
 * would be difficult to demonstrate this even under artificial conditions.)
 *
 * Note: despite needing exclusive lock, it's not an error for the target
 * entry to already exist.  This is because pgssp_store releases and
 * reacquires lock after failing to find a match; so someone else could
 * have made the entry while we waited to get exclusive lock.
 */
static pgsspEntry *
entry_alloc(pgsspHashKey *key, Size query_offset, int query_len, int encoding)
{
	pgsspEntry  *entry;
	bool		found;

	/* Make space if needed */
	while (hash_get_num_entries(pgssp_hash) >= pgssp_max)
		entry_dealloc();

	/* Find or create an entry with desired hash code */
	entry = (pgsspEntry *) hash_search(pgssp_hash, key, HASH_ENTER, &found);

	if (!found)
	{
		/* New entry, initialize it */

		/* reset the statistics */
		memset(&entry->counters, 0, sizeof(Counters));

		/* re-initialize the mutex each time ... we assume no one using it */
		SpinLockInit(&entry->mutex);
		/* ... and don't forget the query text metadata */
		Assert(query_len >= 0);
		entry->query_offset = query_offset;
		entry->query_len = query_len;
		entry->encoding = encoding;
	}

	return entry;
}

/*
 * qsort comparator for sorting into increasing usage order
 */
static int
entry_cmp(const void *lhs, const void *rhs)
{
	double		l_usage = (*(pgsspEntry *const *) lhs)->counters.last_call;
	double		r_usage = (*(pgsspEntry *const *) rhs)->counters.last_call;

	if (l_usage < r_usage)
		return -1;
	else if (l_usage > r_usage)
		return +1;
	else
		return 0;
}

/*
 * Deallocate least-used entries.
 *
 * Caller must hold an exclusive lock on pgssp->lock.
 */
static void
entry_dealloc(void)
{
	HASH_SEQ_STATUS hash_seq;
	pgsspEntry **entries;
	pgsspEntry  *entry;
	int			nvictims;
	int			i;
	Size		tottextlen;
	int			nvalidtexts;

	/*
	 * Sort entries by usage and deallocate USAGE_DEALLOC_PERCENT of them.
	 * While we're scanning the table, apply the decay factor to the usage
	 * values, and update the mean query length.
	 *
	 * Note that the mean query length is almost immediately obsolete, since
	 * we compute it before not after discarding the least-used entries.
	 * Hopefully, that doesn't affect the mean too much; it doesn't seem worth
	 * making two passes to get a more current result.  Likewise, the new
	 * cur_median_usage includes the entries we're about to zap.
	 */


	entries = palloc(hash_get_num_entries(pgssp_hash) * sizeof(pgsspEntry *));

	i = 0;
	tottextlen = 0;
	nvalidtexts = 0;

	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		entries[i++] = entry;

		/* In the mean length computation, ignore dropped texts. */
		if (entry->query_len >= 0)
		{
			tottextlen += entry->query_len + 1;
			nvalidtexts++;
		}
	}

	/* Sort into increasing order by usage */
	qsort(entries, i, sizeof(pgsspEntry *), entry_cmp);

	/* Record the mean query length */
	if (nvalidtexts > 0)
		pgssp->mean_query_len = tottextlen / nvalidtexts;
	else
		pgssp->mean_query_len = ASSUMED_LENGTH_INIT;

	/* Now zap an appropriate fraction of lowest-usage entries */
	nvictims = Max(10, i * USAGE_DEALLOC_PERCENT / 100);
	nvictims = Min(nvictims, i);

	for (i = 0; i < nvictims; i++)
	{
		hash_search(pgssp_hash, &entries[i]->key, HASH_REMOVE, NULL);
	}

	pfree(entries);

	/* trace when evicting entries, if appening too often this can slow queries ...
	 * increasing pg_stat_sql_plans.max value could help */
	 ereport(LOG,
		(errmsg("pg_stat_sql_plans evicting %d entries", nvictims),	 
		errhidecontext(true), errhidestmt(true)));

}

/*
 * Given a query string (not necessarily null-terminated), allocate a new
 * entry in the external query text file and store the string there.
 *
 * If successful, returns true, and stores the new entry's offset in the file
 * into *query_offset.  Also, if gc_count isn't NULL, *gc_count is set to the
 * number of garbage collections that have occurred so far.
 *
 * On failure, returns false.
 *
 * At least a shared lock on pgssp->lock must be held by the caller, so as
 * to prevent a concurrent garbage collection.  Share-lock-holding callers
 * should pass a gc_count pointer to obtain the number of garbage collections,
 * so that they can recheck the count after obtaining exclusive lock to
 * detect whether a garbage collection occurred (and removed this entry).
 */
static bool
qtext_store(const char *query, int query_len,
			Size *query_offset, int *gc_count)
{
	Size		off;
	int			fd;

	/*
	 * We use a spinlock to protect extent/n_writers/gc_count, so that
	 * multiple processes may execute this function concurrently.
	 */
	{
		volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp;

		SpinLockAcquire(&s->mutex);
		off = s->extent;
		s->extent += query_len + 1;
		s->n_writers++;
		if (gc_count)
			*gc_count = s->gc_count;
		SpinLockRelease(&s->mutex);
	}

	*query_offset = off;

	/* Now write the data into the successfully-reserved part of the file */
	fd = OpenTransientFile(pgssp_TEXT_FILE, O_RDWR | O_CREAT | PG_BINARY);
	if (fd < 0)
		goto error;

	if (lseek(fd, off, SEEK_SET) != off)
		goto error;

	if (write(fd, query, query_len) != query_len)
		goto error;
	if (write(fd, "\0", 1) != 1)
		goto error;

	CloseTransientFile(fd);

	/* Mark our write complete */
	{
		volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp;

		SpinLockAcquire(&s->mutex);
		s->n_writers--;
		SpinLockRelease(&s->mutex);
	}

	return true;

error:
	ereport(LOG,
			(errcode_for_file_access(),
			 errmsg("could not write pg_stat_statement file \"%s\": %m",
					pgssp_TEXT_FILE)));

	if (fd >= 0)
		CloseTransientFile(fd);

	/* Mark our write complete */
	{
		volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp;

		SpinLockAcquire(&s->mutex);
		s->n_writers--;
		SpinLockRelease(&s->mutex);
	}

	return false;
}

/*
 * Read the external query text file into a malloc'd buffer.
 *
 * Returns NULL (without throwing an error) if unable to read, eg
 * file not there or insufficient memory.
 *
 * On success, the buffer size is also returned into *buffer_size.
 *
 * This can be called without any lock on pgssp->lock, but in that case
 * the caller is responsible for verifying that the result is sane.
 */
static char *
qtext_load_file(Size *buffer_size)
{
	char	   *buf;
	int			fd;
	struct stat stat;

	fd = OpenTransientFile(pgssp_TEXT_FILE, O_RDONLY | PG_BINARY);
	if (fd < 0)
	{
		if (errno != ENOENT)
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not read pg_stat_statement file \"%s\": %m",
							pgssp_TEXT_FILE)));
		return NULL;
	}

	/* Get file length */
	if (fstat(fd, &stat))
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not stat pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));
		CloseTransientFile(fd);
		return NULL;
	}

	/* Allocate buffer; beware that off_t might be wider than size_t */
	if (stat.st_size <= MaxAllocHugeSize)
		buf = (char *) malloc(stat.st_size);
	else
		buf = NULL;
	if (buf == NULL)
	{
		ereport(LOG,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory"),
				 errdetail("Could not allocate enough memory to read pg_stat_statement file \"%s\".",
						   pgssp_TEXT_FILE)));
		CloseTransientFile(fd);
		return NULL;
	}

	/*
	 * OK, slurp in the file.  If we get a short read and errno doesn't get
	 * set, the reason is probably that garbage collection truncated the file
	 * since we did the fstat(), so we don't log a complaint --- but we don't
	 * return the data, either, since it's most likely corrupt due to
	 * concurrent writes from garbage collection.
	 */
	errno = 0;
	if (read(fd, buf, stat.st_size) != stat.st_size)
	{
		if (errno)
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not read pg_stat_statement file \"%s\": %m",
							pgssp_TEXT_FILE)));
		free(buf);
		CloseTransientFile(fd);
		return NULL;
	}

	CloseTransientFile(fd);

	*buffer_size = stat.st_size;
	return buf;
}

/*
 * Locate a query text in the file image previously read by qtext_load_file().
 *
 * We validate the given offset/length, and return NULL if bogus.  Otherwise,
 * the result points to a null-terminated string within the buffer.
 */
static char *
qtext_fetch(Size query_offset, int query_len,
			char *buffer, Size buffer_size)
{
	/* File read failed? */
	if (buffer == NULL)
		return NULL;
	/* Bogus offset/length? */
	if (query_len < 0 ||
		query_offset + query_len >= buffer_size)
		return NULL;
	/* As a further sanity check, make sure there's a trailing null */
	if (buffer[query_offset + query_len] != '\0')
		return NULL;
	/* Looks OK */
	return buffer + query_offset;
}

/*
 * Do we need to garbage-collect the external query text file?
 *
 * Caller should hold at least a shared lock on pgssp->lock.
 */
static bool
need_gc_qtexts(void)
{
	Size		extent;

	/* Read shared extent pointer */
	{
		volatile pgsspSharedState *s = (volatile pgsspSharedState *) pgssp;

		SpinLockAcquire(&s->mutex);
		extent = s->extent;
		SpinLockRelease(&s->mutex);
	}

	/* Don't proceed if file does not exceed 512 bytes per possible entry */
	if (extent < 512 * pgssp_max)
		return false;

	/*
	 * Don't proceed if file is less than about 50% bloat.  Nothing can or
	 * should be done in the event of unusually large query texts accounting
	 * for file's large size.  We go to the trouble of maintaining the mean
	 * query length in order to prevent garbage collection from thrashing
	 * uselessly.
	 */
	if (extent < pgssp->mean_query_len * pgssp_max * 2)
		return false;

	return true;
}

/*
 * Garbage-collect orphaned query texts in external file.
 *
 * This won't be called often in the typical case, since it's likely that
 * there won't be too much churn, and besides, a similar compaction process
 * occurs when serializing to disk at shutdown or as part of resetting.
 * Despite this, it seems prudent to plan for the edge case where the file
 * becomes unreasonably large, with no other method of compaction likely to
 * occur in the foreseeable future.
 *
 * The caller must hold an exclusive lock on pgssp->lock.
 *
 * At the first sign of trouble we unlink the query text file to get a clean
 * slate (although existing statistics are retained), rather than risk
 * thrashing by allowing the same problem case to recur indefinitely.
 */
static void
gc_qtexts(void)
{
	char	   *qbuffer;
	Size		qbuffer_size;
	FILE	   *qfile = NULL;
	HASH_SEQ_STATUS hash_seq;
	pgsspEntry  *entry;
	Size		extent;
	int			nentries;

	/*
	 * When called from pgssp_store, some other session might have proceeded
	 * with garbage collection in the no-lock-held interim of lock strength
	 * escalation.  Check once more that this is actually necessary.
	 */
	if (!need_gc_qtexts())
		return;

	/*
	 * Load the old texts file.  If we fail (out of memory, for instance),
	 * invalidate query texts.  Hopefully this is rare.  It might seem better
	 * to leave things alone on an OOM failure, but the problem is that the
	 * file is only going to get bigger; hoping for a future non-OOM result is
	 * risky and can easily lead to complete denial of service.
	 */
	qbuffer = qtext_load_file(&qbuffer_size);
	if (qbuffer == NULL)
		goto gc_fail;

	/*
	 * We overwrite the query texts file in place, so as to reduce the risk of
	 * an out-of-disk-space failure.  Since the file is guaranteed not to get
	 * larger, this should always work on traditional filesystems; though we
	 * could still lose on copy-on-write filesystems.
	 */
	qfile = AllocateFile(pgssp_TEXT_FILE, PG_BINARY_W);
	if (qfile == NULL)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not write pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));
		goto gc_fail;
	}

	extent = 0;
	nentries = 0;

	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		int			query_len = entry->query_len;
		char	   *qry = qtext_fetch(entry->query_offset,
									  query_len,
									  qbuffer,
									  qbuffer_size);

		if (qry == NULL)
		{
			/* Trouble ... drop the text */
			entry->query_offset = 0;
			entry->query_len = -1;
			/* entry will not be counted in mean query length computation */
			continue;
		}

		if (fwrite(qry, 1, query_len + 1, qfile) != query_len + 1)
		{
			ereport(LOG,
					(errcode_for_file_access(),
					 errmsg("could not write pg_stat_statement file \"%s\": %m",
							pgssp_TEXT_FILE)));
			hash_seq_term(&hash_seq);
			goto gc_fail;
		}

		entry->query_offset = extent;
		extent += query_len + 1;
		nentries++;
	}

	/*
	 * Truncate away any now-unused space.  If this fails for some odd reason,
	 * we log it, but there's no need to fail.
	 */
	if (ftruncate(fileno(qfile), extent) != 0)
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not truncate pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));

	if (FreeFile(qfile))
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not write pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));
		qfile = NULL;
		goto gc_fail;
	}

	elog(DEBUG1, "pgssp gc of queries file shrunk size from %zu to %zu",
		 pgssp->extent, extent);

	/* Reset the shared extent pointer */
	pgssp->extent = extent;

	/*
	 * Also update the mean query length, to be sure that need_gc_qtexts()
	 * won't still think we have a problem.
	 */
	if (nentries > 0)
		pgssp->mean_query_len = extent / nentries;
	else
		pgssp->mean_query_len = ASSUMED_LENGTH_INIT;

	free(qbuffer);

	/*
	 * OK, count a garbage collection cycle.  (Note: even though we have
	 * exclusive lock on pgssp->lock, we must take pgssp->mutex for this, since
	 * other processes may examine gc_count while holding only the mutex.
	 * Also, we have to advance the count *after* we've rewritten the file,
	 * else other processes might not realize they read a stale file.)
	 */
	record_gc_qtexts();

	return;

gc_fail:
	/* clean up resources */
	if (qfile)
		FreeFile(qfile);
	if (qbuffer)
		free(qbuffer);

	/*
	 * Since the contents of the external file are now uncertain, mark all
	 * hashtable entries as having invalid texts.
	 */
	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		entry->query_offset = 0;
		entry->query_len = -1;
	}

	/*
	 * Destroy the query text file and create a new, empty one
	 */
	(void) unlink(pgssp_TEXT_FILE);
	qfile = AllocateFile(pgssp_TEXT_FILE, PG_BINARY_W);
	if (qfile == NULL)
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not write new pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));
	else
		FreeFile(qfile);

	/* Reset the shared extent pointer */
	pgssp->extent = 0;

	/* Reset mean_query_len to match the new state */
	pgssp->mean_query_len = ASSUMED_LENGTH_INIT;

	/*
	 * Bump the GC count even though we failed.
	 *
	 * This is needed to make concurrent readers of file without any lock on
	 * pgssp->lock notice existence of new version of file.  Once readers
	 * subsequently observe a change in GC count with pgssp->lock held, that
	 * forces a safe reopen of file.  Writers also require that we bump here,
	 * of course.  (As required by locking protocol, readers and writers don't
	 * trust earlier file contents until gc_count is found unchanged after
	 * pgssp->lock acquired in shared or exclusive mode respectively.)
	 */
	record_gc_qtexts();
}

/*
 * Release all entries.
 */
static void
entry_reset(void)
{
	HASH_SEQ_STATUS hash_seq;
	pgsspEntry  *entry;
	FILE	   *qfile;

	LWLockAcquire(pgssp->lock, LW_EXCLUSIVE);

	hash_seq_init(&hash_seq, pgssp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		hash_search(pgssp_hash, &entry->key, HASH_REMOVE, NULL);
	}

	/*
	 * Write new empty query file, perhaps even creating a new one to recover
	 * if the file was missing.
	 */
	qfile = AllocateFile(pgssp_TEXT_FILE, PG_BINARY_W);
	if (qfile == NULL)
	{
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not create pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));
		goto done;
	}

	/* If ftruncate fails, log it, but it's not a fatal problem */
	if (ftruncate(fileno(qfile), 0) != 0)
		ereport(LOG,
				(errcode_for_file_access(),
				 errmsg("could not truncate pg_stat_statement file \"%s\": %m",
						pgssp_TEXT_FILE)));

	FreeFile(qfile);

done:
	pgssp->extent = 0;
	/* This counts as a query text garbage collection for our purposes */
	record_gc_qtexts();

	LWLockRelease(pgssp->lock);
}


/*
 * Look for these operator characters in order to decide whether to strip
 * whitespaces which are needless from the view of sql syntax in
 * normalize_expr(). This must be synced with op_chars in scan.l.
 */
#define OPCHARS "~!@#^&|`?+-*/%<>="
#define IS_WSCHAR(c) ((c) == ' ' || (c) == '\n' || (c) == '\t')
#define IS_CONST(tok) (tok == FCONST || tok == SCONST || tok == BCONST || \
			tok == XCONST || tok == ICONST || tok == NULL_P || \
		    tok == TRUE_P || tok == FALSE_P || \
			tok == CURRENT_DATE || tok == CURRENT_TIME || \
		    tok == LOCALTIME || tok == LOCALTIMESTAMP)
#define IS_INDENTED_ARRAY(v) ((v) == P_GroupKeys || (v) == P_HashKeys)

/*
 * norm_yylex: core_yylex with replacing some tokens.
 */
static int
norm_yylex(char *str, core_YYSTYPE *yylval, YYLTYPE *yylloc, core_yyscan_t yyscanner)
{
	int tok;

	PG_TRY();
	{
		tok = core_yylex(yylval, yylloc, yyscanner);
	}
	PG_CATCH();
	{
		/*
		 * Error might occur during parsing quoted tokens that chopped
		 * halfway. Just ignore the rest of this query even if there might
		 * be other reasons for parsing to fail.
		 */
		FlushErrorState();
		return -1;
	}
	PG_END_TRY();

	/*
	 * '?' alone is assumed to be an IDENT.  If there's a real
	 * operator '?', this should be confused but there's hardly be.
	 */
	if (tok == Op && str[*yylloc] == '?' &&
		strchr(OPCHARS, str[*yylloc + 1]) == NULL)
		tok = SCONST;

	/*
	 * Replace tokens with '=' if the operator is consists of two or
	 * more opchars only. Assuming that opchars do not compose a token
	 * with non-opchars, check the first char only is sufficient.
	 */
	if (tok == Op && strchr(OPCHARS, str[*yylloc]) != NULL)
		tok = '=';

	return tok;
}

/*
 * normalize_expr - Normalize statements or expressions.
 *
 * Mask constants, strip unnecessary whitespaces and upcase keywords. expr is
 * modified in-place (destructively). If readability is more important than
 * uniqueness, preserve_space puts one space for one existent whitespace for
 * more readability.
 */
void
normalize_expr(char *expr, bool preserve_space)
{
	core_yyscan_t yyscanner;
	core_yy_extra_type yyextra;
	core_YYSTYPE yylval;
	YYLTYPE		yylloc;
	YYLTYPE		lastloc;
	YYLTYPE start;
	char *wp;
	int			tok, lasttok;

	wp = expr;
	yyscanner = scanner_init(expr,
							 &yyextra,
							 ScanKeywords,
							 NumScanKeywords);

	/*
	 * The warnings about nonstandard escape strings is already emitted in the
	 * core. Just silence them here.
	 */
#if PG_VERSION_NUM >= 90500
	yyextra.escape_string_warning = false;
#endif
	lasttok = 0;
	lastloc = -1;

	for (;;)
	{
		tok = norm_yylex(expr, &yylval, &yylloc, yyscanner);

		start = yylloc;

		if (lastloc >= 0)
		{
			int i, i2;

			/* Skipping preceding whitespaces */
			for(i = lastloc ; i < start && IS_WSCHAR(expr[i]) ; i++);

			/* Searching for trailing whitespace */
			for(i2 = i; i2 < start && !IS_WSCHAR(expr[i2]) ; i2++);

			if (lasttok == IDENT)
			{
				/* Identifiers are copied in case-sensitive manner. */
				memcpy(wp, expr + i, i2 - i);
				wp += i2 - i;
			}
			else
			{
				/* Upcase keywords */
				char *sp;
				for (sp = expr + i ; sp < expr + i2 ; sp++, wp++)
					*wp = (*sp >= 'a' && *sp <= 'z' ?
						   *sp - ('a' - 'A') : *sp);
			}

			/*
			 * Because of destructive writing, wp must not go advance the
			 * reading point.
			 * Although this function's output does not need any validity as a
			 * statement or an expression, spaces are added where it should be
			 * to keep some extent of sanity.  If readability is more important
			 * than uniqueness, preserve_space adds one space for each
			 * existent whitespace.
			 */
			if (tok > 0 &&
				i2 < start &&
				(preserve_space || 
				 (tok >= IDENT && lasttok >= IDENT &&
				  !IS_CONST(tok) && !IS_CONST(lasttok))))
				*wp++ = ' ';

			start = i2;
		}

		/* Exit on parse error. */
		if (tok < 0)
		{
			*wp = 0;
			return;
		}

		/*
		 * Negative signs before numbers are tokenized separately. And
		 * explicit positive signs won't appear in deparsed expressions.
		 */
		if (tok == '-')
			tok = norm_yylex(expr, &yylval, &yylloc, yyscanner);

		/* Exit on parse error. */
		if (tok < 0)
		{
			*wp = 0;
			return;
		}

		if (IS_CONST(tok))
		{
			YYLTYPE end;

			tok = norm_yylex(expr, &yylval, &end, yyscanner);

			/* Exit on parse error. */
			if (tok < 0)
			{
				*wp = 0;
				return;
			}

			/*
			 * Negative values may be surrounded with parens by the
			 * deparser. Mask involving them.
			 */
			if (lasttok == '(' && tok == ')')
			{
				wp -= (start - lastloc);
				start = lastloc;
				end++;
			}

			while (expr[end - 1] == ' ') end--;

			*wp++ = '?';
			yylloc = end;
		}

		if (tok == 0)
			break;

		lasttok = tok;
		lastloc = yylloc;
	}
	*wp = 0;
}

static uint64
hash_query(const char* query)
{
	uint64 queryid;

	char *normquery = pstrdup(query);
	normalize_expr(normquery, true);
	queryid = DatumGetUInt64(hash_any_extended((const unsigned char*)normquery, strlen(normquery),0));
	pfree(normquery);

	return queryid;
}


Datum
pgssp_normalize_query(PG_FUNCTION_ARGS)
{
	text *query = PG_GETARG_TEXT_P(0);
	char *cquery = text_to_cstring(query);
	char *normquery = pstrdup(cquery);
	normalize_expr(normquery, true);
	PG_RETURN_TEXT_P(cstring_to_text(normquery));
	pfree(normquery);
}

Datum
pgssp_backend_queryid(PG_FUNCTION_ARGS)
{
	int i;

	for (i = 0; i < ProcGlobal->allProcCount; i++)
	{
		PGPROC  *proc = &ProcGlobal->allProcs[i];
		if (proc != NULL && proc->pid != 0 && proc->pid == PG_GETARG_INT32(0))
		{
			return ProcEntryArray[i].queryid;
		}
	}
	return 0;
}
