Name: snac
Version: 0.4.1
Release: 1.bigswitch
Summary: SNAC OpenFlow controller

Group: Applications/Networking
License: GPL
Source0: snac-nox.tar.gz
Source1: snac.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf >= 2.59
BuildRequires: automake >= 1.9.6
BuildRequires: libtool
BuildRequires: boost-devel >= 1.34.1
BuildRequires: sqlite-devel
BuildRequires: swig >= 1.3.0
BuildRequires: openssl-devel
BuildRequires: xerces-c-devel
BuildRequires: python-sphinx
BuildRequires: openldap-devel
BuildRequires: java-openjdk
BuildRequires: python-devel >= 2.4
BuildRequires: python-mako
BuildRequires: python-twisted-web
BuildRequires: python-simplejson
Requires: boost >= 1.34.1
Requires: python >= 2.4
Requires: python-mako
Requires: python-twisted-web
Requires: python-simplejson
Requires: openflow-pki

%description
SNAC OpenFlow controller

%post
/sbin/ldconfig
# Obtain keys and certificates for NOX within the OpenFlow PKI.
cd %{_sysconfdir}/nox
if test ! -e cacert.pem; then
    ln -sf %{_datadir}/openflow/pki/controllerca/cacert.pem cacert.pem
fi
if test ! -e privkey.pem || test ! -e cert.pem; then
    oldumask=$(umask)
    umask 077
    ofp-pki req+sign tmp controller >/dev/null
    mv tmp-privkey.pem privkey.pem
    mv tmp-cert.pem cert.pem
    mv tmp-req.pem req.pem
    chmod go+r cert.pem req.pem
    umask $oldumask
fi
# Generate self-signed certificate for NOX as an SSL webserver.
cd %{_sysconfdir}/nox
if test ! -e noxca.key.insecure || test ! -e noxca.cert; then
    gen-nox-cert.sh %{_datadir}/
fi
true

%postun
/sbin/ldconfig
true

%prep
%setup -q -n snac-nox -a 1
mv snac src/nox/ext
sed -i 's/$(bindir)/$(libdir)/g;s/^AM_LDFLAGS = -R.*/AM_LDFLAGS =/' src/Make.vars src/nox/ext/Make.vars

%build
autoreconf -Wno-portability --install -I config --force
%configure --enable-ndebug --with-python=yes
( cd src/nox/ext; %configure --enable-ndebug --with-python=yes )
make %{?_smp_mflags} all html
make %{?_smp_mflags} -C src/nox/ext all

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
make -C src/nox/ext install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT%{_libdir} -name \*.la | xargs rm

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc COPYING LICENSE INSTALL README src/nox/ext/doc/* doc/manual/build/html
%config %{_sysconfdir}/nox
%{_bindir}/*
%{_libdir}/libnox*.so*
%{_libdir}/nox
%{_datadir}/nox*
%{_mandir}/man*/*

%changelog
