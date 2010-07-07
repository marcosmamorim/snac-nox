AC_DEFUN([CHECK_LOG4CXX], [
AC_ARG_ENABLE(
  [log4cxx],
  [AC_HELP_STRING([--enable-log4cxx],
                  [Use log4cxx logging infrastructure])],
  [case "${enableval}" in # (
     yes) log4cxx=true ;; # (
     no)  log4cxx=false ;; # (
     *) AC_MSG_ERROR([bad value ${enableval} for --enable-log4cxx]) ;;
   esac],
  [log4cxx=false])

  AM_CONDITIONAL([LOG4CXX_ENABLED], [test "x$log4cxx" = "xtrue"])

  if test "x$log4cxx" = "xtrue"; then
      AC_DEFINE(LOG4CXX_ENABLED,1,[
Provide macro indicating the preference to use log4cxx
])
  fi
])
