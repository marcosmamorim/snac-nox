include ../../../Make.vars 

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

EXTRA_DIST =\
	meta.xml

pkglib_LTLIBRARIES =		\
	bcast_resolve.la	

bcast_resolve_la_CPPFLAGS =						\
	$(AM_CPPFLAGS)							\
	-I$(srcdir)/../							\
	-I$(top_srcdir)/src/nox						\
	-D__COMPONENT_FACTORY_FUNCTION__=bcast_resolve_get_factory

bcast_resolve_la_SOURCES = bcast-resolve.cc bcast-resolve.hh
bcast_resolve_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

all-local: nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
