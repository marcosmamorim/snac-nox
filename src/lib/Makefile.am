include ../Make.vars

lib_LTLIBRARIES = libnoxcore.la

EXTRA_DIST =	\
	dh1024.pem\
	dh2048.pem\
	dh4096.pem

if PY_ENABLED
AM_CPPFLAGS += $(PYTHON_CPPFLAGS)
endif # PY_ENABLED
AM_CPPFLAGS += $(OPENFLOW_CPPFLAGS)

libnoxcore_la_SOURCES = \
	async_file.cc \
	async_io.cc \
	auto_fd.cc \
	buffer.cc \
	command-line.cc \
	errno_exception.cc \
	event-dispatcher.cc \
	event.cc \
	expr.cc \
	fault.cc \
	flow.cc \
	flow-stats-in.cc \
	leak-checker.cc \
	netinet++/ethernetaddr.cc \
	openflow-event.cc \
	openflow.cc \
	packetgen.cc \
	poll-loop.cc \
	ppoll.cc \
	resolver.cc \
	sigset.cc \
	string.cc \
	ssl-config.cc \
	ssl-socket.cc \
	tcp-socket.cc \
	threads/cooperative.cc \
	threads/impl.cc \
	threads/native.cc \
	threads/signals.cc \
	timer-dispatcher.cc \
	timeval.cc \
	dhparams.h \
	xml-util.cc

nodist_libnoxcore_la_SOURCES = dhparams.c
dhparams.c: dh1024.pem dh2048.pem dh4096.pem
	(echo '#include "dhparams.h"' &&			\
	 openssl dhparam -C -in $(srcdir)/dh1024.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/dh2048.pem -noout &&	\
	 openssl dhparam -C -in $(srcdir)/dh4096.pem -noout)	\
	| sed 's/\(get_dh[0-9]*\)()/\1(void)/' > dhparams.c.tmp
	mv dhparams.c.tmp dhparams.c

if HAVE_NETLINK
libnoxcore_la_SOURCES += \
	datapath.cc \
	netlink.cc
endif

if HAVE_PCAP
libnoxcore_la_SOURCES += \
	pcapreader.cc
endif

libnoxcore_la_LIBADD = -lpthread $(PCAP_LDFLAGS) $(SSL_LIBS)  -lcrypto -lxerces-c
libnoxcore_la_LDFLAGS = $(AM_LDFLAGS) $(BOOST_LDFLAGS) $(XERCES_LDFLAGS)

if PY_ENABLED
libnoxcore_la_LIBADD += $(PYTHON_EXTRA_LDFLAGS) $(PYTHON_EXTRA_LIBS) $(PYTHON_LDFLAGS)
endif

if LOG4CXX_ENABLED
libnoxcore_la_LIBADD += 				
libnoxcore_la_SOURCES +=				\
	vlog-log4cxx.cc

else
libnoxcore_la_SOURCES +=				\
	vlog.cc					\
	vlog-socket.cc
endif

install-exec-hook:
	@list='$(lib_LTLIBRARIES)'; for p in $$list; do \
	  if test -f $$p; then \
	    f=$(am__strip_dir) \
		echo $(DESTDIR)$(libdir)/$$f \
	  else :; fi; \
	done
