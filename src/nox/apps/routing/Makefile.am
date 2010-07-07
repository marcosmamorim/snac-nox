include ../../../Make.vars 

EXTRA_DIST = meta.xml		\
	routing.i		\
	nat_enforcer.i		\
	samplerouting.py	\
	__init__.py

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

pkglib_LTLIBRARIES =		\
	routing_module.la	\
	nat_enforcer.la		\
	sprouting.la

nat_enforcer_la_CPPFLAGS =							\
	$(AM_CPPFLAGS)								\
	-I$(srcdir)/../								\
	-I$(top_srcdir)/src/nox							\
	-D__COMPONENT_FACTORY_FUNCTION__=nat_enforcer_get_factory

nat_enforcer_la_SOURCES = nat_enforcer.hh nat_enforcer.cc
nat_enforcer_la_LDFLAGS = -module -export-dynamic

routing_module_la_CPPFLAGS =							\
	$(AM_CPPFLAGS)								\
	-I$(srcdir)/../								\
	-I$(top_srcdir)/src/nox							\
	-D__COMPONENT_FACTORY_FUNCTION__=routing_module_get_factory

routing_module_la_SOURCES = routing.cc routing.hh
routing_module_la_LDFLAGS = -module -export-dynamic

sprouting_la_CPPFLAGS =								\
	$(AM_CPPFLAGS)								\
	-I$(srcdir)/../								\
	-I$(top_srcdir)/src/nox							\
	-D__COMPONENT_FACTORY_FUNCTION__=sprouting_get_factory

sprouting_la_SOURCES = sprouting.cc sprouting.hh                   
sprouting_la_LDFLAGS = -module -export-dynamic

NOX_RUNTIMEFILES = meta.xml

if PY_ENABLED
pyrouting_wrap_includes = 	\
	routing.i

pyrouting_wrap.cc pyrouting.py: $(pyrouting_wrap_includes)
	$(SWIG) $(SWIG_PYTHON_OPT)  -I$(top_srcdir)/src/nox/lib/ $(OPENFLOW_CPPFLAGS) -outdir $(builddir)/. -o pyrouting_wrap.cc -module pyrouting $(srcdir)/routing.i

pkglib_LTLIBRARIES += _pyrouting.la
_pyrouting_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox/ -I$(srcdir)/../ -I$(top_builddir)/src/nox/
_pyrouting_la_SOURCES = pyrouting.cc pyrouting.hh
nodist__pyrouting_la_SOURCES = pyrouting_wrap.cc pyrouting.py
_pyrouting_la_LDFLAGS = -module

pynatenforcer_wrap_includes =	\
	nat_enforcer.i

pynatenforcer_wrap.cc pynatenforcer.py: $(pynatenforcer_wrap_includes)
	swig -I$(top_srcdir)/src/nox/lib/ -I$(top_srcdir)/src/nox/apps/ -outdir $(builddir)/. -o pynatenforcer_wrap.cc -c++ -python -module pynatenforcer $(srcdir)/nat_enforcer.i

pkglib_LTLIBRARIES += _pynatenforcer.la
_pynatenforcer_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/nox -I$(srcdir)/../ -I$(top_builddir)/src/nox/
_pynatenforcer_la_SOURCES = pynat_enforcer.hh pynat_enforcer.cc
nodist__pynatenforcer_la_SOURCES = pynatenforcer_wrap.cc
_pynatenforcer_la_LDFLAGS = -module

NOX_RUNTIMEFILES+=		\
	__init__.py 		\
	samplerouting.py

NOX_PYBUILDFILES =		\
	pyrouting_wrap.cc 	\
	pyrouting.py		\
	pynatenforcer_wrap.cc	\
	pynatenforcer.py

NOX_PYLIBFILES = 		\
	_pyrouting.so		\
	_pynatenforcer.so

endif # PY_ENABLED

all-local:  nox-all-local
clean-local: nox-clean-local
install-exec-hook: nox-install-local
