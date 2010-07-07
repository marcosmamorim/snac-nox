include ../../../Make.vars 

EXTRA_DIST = meta.xml \
	__init__.py \
	networkeventsws.py \
	py_uel_memleak_test.py \
	pyuser_event_log.i \
	simple_uel_util.py \
    static_www \
	UI_user_event_log.py 

pkglib_LTLIBRARIES =		\
	user_event_log.la \
	uel_memleak_test.la \
	user_event_log_test2.la

user_event_log_la_CPPFLAGS =							\
	$(AM_CPPFLAGS)								\
	-I $(top_srcdir)/src/nox						\
	-I $(top_srcdir)/src/include						\
	-I $(top_srcdir)/src/nox/apps/						\
	-D__COMPONENT_FACTORY_FUNCTION__=user_event_log_get_factory

user_event_log_la_SOURCES = user_event_log.cc user_event_log.hh log_entry.hh
user_event_log_la_LDFLAGS = -module -export-dynamic

user_event_log_test2_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox \
				-I $(top_srcdir)/src/nox/apps/
user_event_log_test2_la_SOURCES = user_event_log_test2.cc 
user_event_log_test2_la_LDFLAGS = -module -export-dynamic

uel_memleak_test_la_CPPFLAGS = $(AM_CPPFLAGS) -I $(top_srcdir)/src/nox \
				-I $(top_srcdir)/src/nox/apps/
uel_memleak_test_la_SOURCES = uel_memleak_test.cc 
uel_memleak_test_la_LDFLAGS = -module -export-dynamic

# Required for static_www build/install
MODULE=user_event_log
MODULE_BASE_PATH=nox/apps
MODULE_BASE_ESCAPE=../..


NOX_RUNTIMEFILES = meta.xml

if PY_ENABLED

AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
NOX_RUNTIMEFILES += __init__.py \
										UI_user_event_log.py \
										py_uel_memleak_test.py \
										simple_uel_util.py \
										networkeventsws.py

NOX_PYBUILDFILES = pyuser_event_log.py 
	

pyuser_event_log_wrap.cc pyuser_event_log.py: pyuser_event_log.i 
		swig -I$(top_srcdir)/src/nox/lib/ -outdir $(builddir)/. -o pyuser_event_log_wrap.cc -c++ -python -module pyuser_event_log $(srcdir)/pyuser_event_log.i

pkglib_LTLIBRARIES += _pyuser_event_log.la
_pyuser_event_log_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(srcdir)/../ -I$(top_builddir)/src/nox/
_pyuser_event_log_la_SOURCES = user_event_log_proxy.cc user_event_log_proxy.hh
nodist__pyuser_event_log_la_SOURCES = pyuser_event_log_wrap.cc
_pyuser_event_log_la_LDFLAGS = -module

NOX_PYLIBFILES = _pyuser_event_log.so

endif # PY_ENABLED

all-local: nox-runtimefiles-build static-www-build nox-all-local
clean-local: nox-runtimefiles-clean static-www-clean nox-clean-local
install-exec-hook: nox-install-local
