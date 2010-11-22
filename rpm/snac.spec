Name: snac
Version: 0.4.0.devel
Release: 1%{?dist}
Summary: SNAC/NOX

%define snac_nox_version 4ba406f
%define snac_version d74545d

Group: Applications/Networking
License: GPL
Source0: bigswitch-snac-nox-%{snac_nox_version}.tar.gz
Source1: bigswitch-snac-%{snac_version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

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
BuildRequires: autoconf >= 2.59
BuildRequires: automake >= 1.9.6
BuildRequires: libtool
Requires: boost >= 1.34.1
Requires: python >= 2.4
Requires: python-mako
Requires: python-twisted-web
Requires: python-simplejson

%description
SNAC/NOX

%prep
%setup -q -n bigswitch-snac-nox-%{snac_nox_version} -b 0 -a 1
mv bigswitch-snac-%{snac_version} src/nox/ext
sed -i 's/$(bindir)/$(libdir)/g;s/^AM_LDFLAGS = -R.*/AM_LDFLAGS =/' src/Make.vars src/nox/ext/Make.vars

%build
./boot.sh --enable-ext
%configure --enable-ndebug --with-python=yes
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc



%changelog
