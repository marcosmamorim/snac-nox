include Make.vars

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I config
EXTRA_DIST =	\
	LICENSE					\
	builtin/components.xsd			\
	builtin/nox.xsd
SUBDIRS = include lib nox utilities tests etc

bin_PROGRAMS = nox_core
pkglib_LTLIBRARIES =

AM_CPPFLAGS += -I$(srcdir)/nox

nox_core_SOURCES = 				\
	components.xsd.cc			\
	nox.xsd.cc				\
	nox_main.cc				\
	nox/component.hh			\
	nox/deployer.hh				\
	nox/dso-deployer.hh			\
	nox/kernel.hh				\
	nox/nox.hh				\
	nox/packet-classifier.hh		\
	nox/static-deployer.hh			\
	builtin/deployer.cc			\
	builtin/component.cc			\
	builtin/dso-deployer.cc			\
	builtin/event-dispatcher-component.cc	\
	builtin/event-dispatcher-component.hh	\
	builtin/kernel.cc			\
	builtin/nox.cc				\
	builtin/packet-classifier.cc		\
	builtin/static-deployer.cc

CLEANFILES =					\
	components.xsd.cc			\
	nox.xsd.cc
components.xsd.cc: builtin/components.xsd utilities/text2cc
	$(srcdir)/utilities/text2cc					    \
		deployer.hh vigil Deployer::COMPONENTS_CONFIGURATION_SCHEMA \
		< $(srcdir)/builtin/components.xsd			    \
		> components.xsd.cc
nox.xsd.cc: builtin/nox.xsd utilities/text2cc
	$(srcdir)/utilities/text2cc					\
		nox_main.hh vigil::main platform_configuration_schema	\
		< $(srcdir)/builtin/nox.xsd				\
		> nox.xsd.cc

nox_core_LDFLAGS = $(AM_LDFLAGS) $(BOOST_LDFLAGS) 		\
	$(BOOST_UNIT_TEST_FRAMEWORK_LIB) 			\
	$(BOOST_FILESYSTEM_LIB) 				\
	$(BOOST_SERIALIZATION_LIB) 				\
	$(SSL_LIBS)                             		\
	$(XERCES_LDFLAGS) -Wl,-E
nox_core_LDADD = $(builddir)/lib/libnoxcore.la			\
	$(LIBADD_DL)						\
	$(LDADD)
nox_core_DEPENDENCIES = 

if LOG4CXX_ENABLED
nox_core_LDADD +=						\
	$(builddir)/nox/thirdparty/apache-log4cxx/src/main/cpp/liblog4cxx.la
endif

if USE_LTDL
nox_core_LDFLAGS += "-dlopen" force
nox_core_LDADD += -lltdl

# To link an application library to the nox_core binary, as a
# prerequisite you have to pass '--enable-ltdl' and '--enable-static'
# for the configure. Plus enable the static linkage of the nox_core
# binary by uncommenting the next line:
#nox_core_LDFLAGS += -static
#
# Then to define the application libraries to link to the nox_core
# binary, per library append a) '"-dlopen" path/to/library.la' to
# nox_core_LDADD and b) 'path/to/library.la' to nox_core_DEPENDENCIES.
# For example:
#nox_core_LDADD += "-dlopen" nox/apps/pyrt/pyrt.la
#nox_core_DEPENDENCIES += nox/apps/pyrt/pyrt.la
#nox_core_LDADD += "-dlopen" nox/apps/bindings_storage/bindings_storage.la
#nox_core_DEPENDENCIES += nox/apps/bindings_storage/bindings_storage.la
#nox_core_LDADD += "-dlopen" nox/apps/tests/tests.la
#nox_core_DEPENDENCIES += nox/apps/tests/tests.la
#nox_core_LDADD += "-dlopen" nox/apps/storage/storage-common.la
#nox_core_DEPENDENCIES += nox/apps/storage/storage-common.la
#nox_core_LDADD += "-dlopen" nox/apps/storage/storage-backend.la
#nox_core_DEPENDENCIES += nox/apps/storage/storage-backend.la
#nox_core_LDADD += "-dlopen" nox/apps/storage/transactional-storage-backend.la
#nox_core_DEPENDENCIES += nox/apps/storage/transactional-storage-backend.la

#nox_core_LDADD += "-dlopen" nox/apps/authenticator/authenticator.la
#nox_core_DEPENDENCIES += nox/apps/authenticator/authenticator.la
#nox_core_LDADD += "-dlopen" nox/apps/bcast_resolve/bcast_resolve.la
#nox_core_DEPENDENCIES += nox/apps/bcast_resolve/bcast_resolve.la
#nox_core_LDADD += "-dlopen" nox/apps/routing/routing.la
#nox_core_DEPENDENCIES += nox/apps/routing/routing.la
#nox_core_LDADD += "-dlopen" nox/apps/topology/topology.la
#nox_core_DEPENDENCIES += nox/apps/topology/topology.la
#nox_core_LDADD += "-dlopen" nox/apps/discovery/link_event.la
#nox_core_DEPENDENCIES += nox/apps/discovery/link_event.la
#nox_core_LDADD += "-dlopen" nox/apps/user_event_log/user_event_log.la
#nox_core_DEPENDENCIES += nox/apps/user_event_log/user_event_log.la

endif

# Doesn't work with DESTDIR (breaks when creating deb package)
#install-data-local:
## Create DWH directories.
#	$(mkinstalldirs) $(pkglocalstatedir)/import
#	$(mkinstalldirs) $(pkglocalstatedir)/export
#	$(mkinstalldirs) $(pkglocalstatedir)/loaded

nox.test:
	echo "#! $(SHELL)" >> $@.tmp
	echo "exec ./nox_core tests" >> $@.tmp
	chmod a+x $@.tmp
	mv $@.tmp $@

TESTS=nox.test

clean-local:
	-rm -f *.test

install-exec-hook: nox-install-local
