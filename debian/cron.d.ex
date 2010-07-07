#
# Regular cron jobs for the nox package
#
0 4	* * *	root	[ -x /usr/bin/nox_maintenance ] && /usr/bin/nox_maintenance
