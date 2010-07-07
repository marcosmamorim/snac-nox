include ../../../Make.vars 

EXTRA_DIST = meta.xml

pkglib_LTLIBRARIES =		\
	noop.la		

noop_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox
noop_la_SOURCES = noop.cc
noop_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml	

all-local: nox-all-local
clean-local: nox-clean-local 
install-exec-hook: nox-install-local
