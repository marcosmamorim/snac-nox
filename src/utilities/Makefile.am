include ../Make.vars

bin_PROGRAMS = 

bin_SCRIPTS = \
	reset-admin-pw \
	nox-monitor \
	switch_command.py

if !LOG4CXX_ENABLED
bin_PROGRAMS += vlogconf 

vlogconf_LDADD = ../lib/libnoxcore.la

if PY_ENABLED
vlogconf_LDADD += $(PYTHON_LDFLAGS) $(PYTHON_EXTRA_LIBS) $(PYTHON_EXTRA_LDFLAGS)
endif # PY_ENABLED

vlogconf_SOURCES = vlog_config.cc
vlogconf_LDFLAGS = $(SSL_LIBS)

endif

dist_noinst_SCRIPTS = 			\
	dot-vm \
	import.py.in \
	monitor \
	nox-monitor \
	start-test-vm \
	stop-test-vm \
	reset-admin-pw \
	switch_command.py \
	text2cc

all-local:

import.py: import.py.in Makefile
	sed -e 's&[@]pkglocalstatedir[@]&$(pkglocalstatedir)&' \
		< $(srcdir)/import.py.in > import.py.tmp
	printf '# Local variables:\n# buffer-read-only: t# End:' \
		>> import.py.tmp
	chmod a+x import.py.tmp
	mv import.py.tmp import.py
