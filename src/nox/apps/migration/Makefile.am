include ../../../Make.vars

EXTRA_DIST =\
	__init__.py \
	migration.py \
	example_plugin.py

NOX_RUNTIMEFILES = __init__.py migration.py example_plugin.py

all-local: nox-runtimefiles-build
clean-local: nox-runtimefiles-clean
install-exec-hook: nox-install-local
