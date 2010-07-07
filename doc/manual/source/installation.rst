.. _installation:

NOX Installation
===============================

Quick Start From Git
--------------------

For those with all the proper dependencies installed (see below) NOX can
be configured and built using standard autoconf procedure:: 

   mkdir nox
   cd nox
   git clone git://noxrepo.org/openflow
   git clone git://noxrepo.org/noxcore
   cd noxcore/
   ./boot.sh
   mkdir build/
   cd build/
   ../configure --with-python=`which python2.5`
   make
   make check

If building from the source tarfile, you don't need to run boot.sh.

It is not absolutely necessary that you build with Python, though
we highly recommend it.

By default, NOX builds with C++ STL debugging checks, which slows down
execution speeds by at least a factor of 10.  For an optimized build,
you'll want to turn this off::

   ./configure --with-python=`which python2.5` --enable-ndebug

Once compiled, the *nox_core* binary will be built in the *src/*
directory.  **Note** that nox_core **must** be run from the *src/*
build directory, and that the build directory must not be moved to a
different place in the file system.  You can verify that it has built
properly by printing out the usage information::

    cd src/
    ./nox_core -h

If you've gotten this far, then you're ready to test your build
(:ref:`install_test`) or get right to using it (:ref:`sec_use`).

Not So Quick Start
-------------------

Dependencies
^^^^^^^^^^^^^^

The NOX team's internal development environment is standardized around
Debian unstable.  While we test releases on other Linux distributions
(Fedora, Gentoo, Ubuntu), FreeBSD and NetBSD, using Debian unstable is
certain to provide the least hassle. 

NOX relies on the following software packages.  All are available under
Debian as apt packages. Other distributions may require them to be
separately installed from source:

* g++ 4.1 or greater
* Boost C++ libraries, v1.34.1 or greater (http://www.boost.org)
* Xerces C++ parser, v2.7.0 or greater (http://xerces.apache.org/xerces-c)

For Twisted Python support (highly recommended) the following additional packages are required.

* SWIG v1.3.0 or greater (http://www.swig.org)
* Python2.5 or greater (http://python.org)
* Twisted Python (http://twistedmatrix.com)

The user interface (web management console) requires

* Mako Templates (http://www.makotemplates.org/)
* Simple JSON (http://www.undefined.org/python/)

.. warning::
   Older versions of swig may have incompatibilities with newer gcc/g++
   versions.  This is known to be a problem with g++4.1 and swig v1.3.29

You may also wish to install libpcap (http://tcpdump.org) for testing
and debugging though it isn't strictly necessary.

Configure Options
^^^^^^^^^^^^^^^^^^

The following options are commonly used in NOX configuration.  Use
./configure ----help for a full listing: 

``--with-python=[yes|no|/path/to/python]`` This will build NOX with
support for Twisted Python bindings.  Many NOX applications require
Twisted support and it provides the simplest API for new developers.  We
highly recommend building NOX with Twisted for new users.

``--enable-ndebug`` This will turn *off* debugging (STL debugging in
particular) and increase performance significantly.  Use this whenever
running NOX operationally.

``--with-openflow=/path/to/openflow`` Provide NOX with a path to the
OpenFlow source tree.  This is only necessary to build against a
version of OpenFlow different from that supplied with NOX.

Distribution Specific Installation Notes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Debian unstable:**

NOX should compile with the following packages::
  
  apt-get build-essential libsqlite3-dev install autoconf automake1.10
  g++-4.2 gcc-4.2 libboost-dev libtool libboost-filesystem-dev
  libpcap-dev libssl-dev make python-dev python-twisted swig
  libxerces-c2-dev libboost-serialization-dev python-mako
  libboost-test-dev openssl python-simplejson python-openssl

To build from git, you will also need to install git::

  apt-get git-core

**Fedora Core 9:+**

From a standard development install, you can build
after installing the following packages::
  
  yum install xerces-c-devel python-twisted libpcap-devel

**Gentoo 2008.0-rc1**

To compile without twisted python you'll need the following packages::
    
  - emerge -av boost
  - emerge -av xerces-c

**OpenSUSE 10.3 :**

The boost distribution that comes with OpenSuse is too old.  You'll have
to install this from the source:

* boost (http://www.boost.org)

To build NOX (with twisted python) you'll have to installed the
following packages from a base install::

  gcc gcc-c++ make libXerces-c-27 libXerces-c-devel
  libpcap-devel libopenssl-devel swig sqlite-devel
  python-devel python-twisted python-curses 

**Mandriva One 2008:**

NOX compiled on Mandriva with the following packages installed::

  libboost-devel boost-1.35.0 libxerces-c-devel
  libopenssl0.9.8-devel libsqlite3-devel libpython2.5-devel
  python-twisted swig-devel

If the swig and swig-devel packages are not available from the repository, you
will have to build swig from source.

.. _install_test:

Testing your build
^^^^^^^^^^^^^^^^^^^^

You can verify that NOX built correct by running::

    make check

From the build directory.  Unittests can be run independently through
the *test* application::

    cd src
    ./nox_core tests

As a simple example, if you've compiled with Twisted try running
*packetdump* using generated traffic::

    cd src/
    ./nox_core -v -i pgen:10 packetdump

This should print out a description of ten identical packets,
and then wait for you to terminate *nox_core* with 'Ctrl-c'.

There currently is no simple way to test the build if it was
not compiled with Python support, besides running it (:ref:`sec_use`).
