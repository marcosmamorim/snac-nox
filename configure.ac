dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(nox, 0.4.0~beta, contact@noxrepo.org)
AC_CONFIG_AUX_DIR(config)

NX_BUILDNR
AH_BOTTOM([/* NOX version with build number, e.g. "1.2.3+build456". */
#define NOX_VERSION VERSION BUILDNR])

AM_INIT_AUTOMAKE([tar-ustar])

AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP

dnl AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AC_DISABLE_STATIC
AC_LIBTOOL_DLOPEN
AC_PROG_LIBTOOL

CHECK_OPENFLOW

AC_CHECK_FUNCS([fdatasync ppoll])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([config.h])

AX_BOOST_BASE([1.34.1])

AX_BOOST_FILESYSTEM
if test "$ax_cv_boost_filesystem" != "yes"; then
   AC_MSG_ERROR([cannot find the Boost::Filesystem library])
fi

AX_LIB_XERCES([2.7.0])
if test "x$HAVE_XERCES" != "xyes"; then
   AC_MSG_ERROR([cannot find the Apache Xerces library])
fi

CHECK_PCAP
CHECK_SSL
CHECK_NDEBUG
CHECK_PROFILING
CHECK_NETLINK
CHECK_THREAD_LOCAL
CHECK_WITH_VM
CHECK_LTDL
CHECK_LOG4CXX
CHECK_MALLOC_HOOKS

dnl --
dnl Module definitions
dnl
dnl All apps are built as modules (actually submodules of "src/nox/app")
dnl
dnl Arguments:
dnl 1. module name (no spaces)
dnl 2. module description (one liner)
dnl 3. space seperated list of dependencies (only partially supported.
dnl    don't use for now
dnl 4. submodules: space separated list. Don't use this unless you
dnl    really know what you're doing
dnl 5. Turn on by default (yes/no)
dnl 6. Subdirectories (broken at the moment, don't use)
dnl --

ACI_MODULE([configuration],[Configuration subsystem],
               [],[],[yes])
ACI_MODULE([tests],[Unit testing framework],
               [],[],[yes])
ACI_MODULE([storage],[Distributed non-persistent and persistent storage],
               [],[],[yes])
ACI_MODULE([storagews],[Webservice interface to storage module],
               [],[],[yes])
ACI_MODULE([user_event_log],[Generate user events at runtime],
               [],[],[yes])
ACI_MODULE([coreui],[User interface],
               [],[],[yes])
ACI_MODULE([noop],[Does nothing],
               [],[],[yes])
ACI_MODULE([bindings_storage],[Manages ndb storage and retrieval of bindingsd data],
               [],[],[yes])
ACI_MODULE([switchstats],[Track runtime switch statistics],
               [],[],[yes])
ACI_MODULE([directory],[directory manager],
               [],[],[yes])

ACI_MODULE([bcast_resolve],[Separate handling of broadcast traffic],
               [],[],[yes])
ACI_MODULE([discovery],[LLDP link discovery],
               [],[],[yes])
ACI_MODULE([topology],[Track network topology],
               [],[],[yes])
ACI_MODULE([authenticator],[Track authenticated hosts],
               [],[],[yes])
ACI_MODULE([routing],[Routing module],
               [],[],[yes])

ACI_MODULE([exit],[Exit oxide after first switch leaves],
               [],[],[yes])
ACI_MODULE([examples],[Set of example apps],
               [],[],[yes])
ACI_MODULE([migration],[cdb migration],
               [],[],[yes])
ACI_MODULE([miscws],[Collection of miscellaneous web services],
               [],[],[yes])
ACI_MODULE([hub],[dumb hub],
               [],[],[yes])
ACI_MODULE([switch],[Learning switch],
               [],[],[yes])
ACI_MODULE([switchconfig],[Handle config of switch ports from the UI],
               [],[],[yes])
ACI_MODULE([simple_c_app],[Example of how to write a c++ app],
               [],[],[yes])
ACI_MODULE([default_switch_approval],[Implements default switch approval mechanism],
               [],[],[yes])
ACI_MODULE([simple_c_py_app],[Example of how to write an integrated c++/python app],
               [],[],[yes])
ACI_MODULE([pyrt],[Python runtime for twisted support],
               [],[],[yes])
ACI_MODULE([flow_fetcher],[Library for fetching flow state from switches],
           [], [], [yes])

dnl TODO automatically generate the following list of submodules
ACI_MODULE([apps],[main source libarary],
               [],
               [configuration pyrt bcast_resolve authenticator
               routing user_event_log userathportal 
               storage storagews tests topology discovery coreui
               simple_c_app simple_c_py_app noop hub switch
               examples migration miscws exit directory default_switch_approval
               bindings_storage switchstats switchconfig flow_fetcher],
               [yes])
ACI_MODULES_VERIFY
dnl Only used for internal testing
dnl ACI_MODULES_SUMMARY
AC_SUBST(MODULES_apps)               

dnl
dnl Conditional checks based on what modules have been turned on.
dnl

if test "$HAVE_pyrt" = "yes"; then
    CHECK_TWISTED
    dnl only check for swig if python was enabled
    if test -n "$PYTHON"; then
        AC_PROG_SWIG(1.3.0)
        if test -z "$SWIG"; then
            AC_MSG_ERROR([When configured with python, NOX requires swig 1.3.0 or later to be installed])
        fi
        SWIG_ENABLE_CXX
        SWIG_PYTHON
    fi    
fi

if test "$HAVE_storage" = "yes"; then
    CHECK_SQLITE3
fi

if test "$HAVE_storage" = "yes"; then
    AX_BOOST_SERIALIZATION
    if test "$ax_cv_boost_serialization" != "yes"; then
       AC_MSG_ERROR([cannot find the Boost::Serialization library])
    fi
fi

if test "$HAVE_tests" = "yes"; then
    AX_BOOST_UNIT_TEST_FRAMEWORK
    if test "$ax_cv_boost_unit_test_framework" != "yes"; then
       AC_MSG_ERROR([cannot find the Boost::Unit_Test_Framework library])
    fi
fi


AC_ARG_ENABLE(
  [noext],
  [AC_HELP_STRING([--enable-noext],
                  [Ignore ext directory even if it exists])],
  [case "${enableval}" in # (
     yes) noext=true ;; # (
     no)  noext=false ;; # (
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-noext]) ;;
   esac],
  [noext=false]
)

if test -d "$srcdir/src/nox/ext/"; then
    if test "$noext" = false; then
        AC_CONFIG_SUBDIRS([src/nox/ext])
    fi
fi

if test "$log4cxx" = true; then
    AC_CONFIG_SUBDIRS([src/nox/thirdparty/apache-log4cxx])
fi

AC_CONFIG_FILES([Makefile 
man/Makefile
man/man1/Makefile
man/man5/Makefile
doc/Makefile
doc/manual/Makefile
src/Makefile
src/etc/Makefile
src/include/Makefile
src/lib/Makefile
src/utilities/Makefile
src/nox/Makefile
src/nox/apps/Makefile
src/nox/lib/Makefile
src/nox/lib/netinet/Makefile
src/nox/lib/packet/Makefile
src/tests/Makefile
src/nox/thirdparty/Makefile
src/nox/thirdparty/py_radix/Makefile

src/nox/apps/directory/Makefile

src/nox/apps/configuration/Makefile
src/nox/apps/tests/Makefile
src/nox/apps/tests/pyunittests/Makefile
src/nox/apps/authenticator/Makefile
src/nox/apps/storage/Makefile
src/nox/apps/storagews/Makefile
src/nox/apps/user_event_log/Makefile
src/nox/apps/coreui/Makefile
src/nox/apps/noop/Makefile
src/nox/apps/bindings_storage/Makefile
src/nox/apps/switchstats/Makefile
src/nox/apps/flow_fetcher/Makefile

src/nox/apps/topology/Makefile
src/nox/apps/routing/Makefile
src/nox/apps/discovery/Makefile
src/nox/apps/bcast_resolve/Makefile

src/nox/apps/simple_c_py_app/Makefile
src/nox/apps/simple_c_app/Makefile
src/nox/apps/pyrt/Makefile
src/nox/apps/switch/Makefile
src/nox/apps/hub/Makefile
src/nox/apps/examples/Makefile
src/nox/apps/migration/Makefile
src/nox/apps/miscws/Makefile
src/nox/apps/switchconfig/Makefile
src/nox/apps/exit/Makefile
src/nox/apps/default_switch_approval/Makefile
])
AC_OUTPUT
