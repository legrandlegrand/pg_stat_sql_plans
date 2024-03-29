# contrib/pg_stat_sql_plans/Makefile

MODULE_big = pg_stat_sql_plans
OBJS = pg_stat_sql_plans.o $(WIN32RES)

EXTENSION = pg_stat_sql_plans
DATA = pg_stat_sql_plans--0.2.sql
PGFILEDESC = "pg_stat_sql_plans - execution statistics of SQL statements"

LDFLAGS_SL += $(filter -lm, $(LIBS))

REGRESS_OPTS = --temp-config $(top_srcdir)/contrib/pg_stat_sql_plans/pg_stat_sql_plans.conf
REGRESS = pg_stat_sql_plans
# Disabled because these tests require "shared_preload_libraries=pg_stat_sql_plans",
# which typical installcheck users do not have (e.g. buildfarm clients).
NO_INSTALLCHECK = 1

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_stat_sql_plans
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
