#-------------------------------------------------------------------------
#
# Makefile for src/bin/pg_keygen
#
# Copyright (c) 1998-2019, PostgreSQL Global Development Group
#
# src/bin/pg_keygen/Makefile
#
#-------------------------------------------------------------------------

PGFILEDESC = "pg_keygen - cluster encryption key generator"
PGAPPICON=win32

subdir = src/bin/pg_keygen
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS= pg_keygen.o $(WIN32RES)

all: pg_keygen

pg_keygen: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

install: all installdirs
	$(INSTALL_PROGRAM) pg_keygen$(X) '$(DESTDIR)$(bindir)/pg_keygen$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pg_keygen$(X)'

clean distclean maintainer-clean:
	rm -f pg_keygen$(X) $(OBJS)
	rm -rf tmp_check

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
