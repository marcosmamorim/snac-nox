Name: openflow
Version: 1.0.0
Release: 1%{?dist}
Summary: OpenFlow

Group: Applications/Networking
License: GPL
Source0: openflow-1.0.0.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf >= 2.59
BuildRequires: automake >= 1.9.6
BuildRequires: libtool
BuildRequires: openssl-devel
Requires: openssl

%description
OpenFlow

%prep
%setup -q
sed -i 's/^AC_PREREQ(2.60)/AC_PREREQ(2.59)/;s/^AC_PROG_MKDIR_P/dnl AC_PROG_MKDIR_P/;/^AM_INIT_AUTOMAKE/a\AC_GNU_SOURCE' configure.ac
sed -i 's/AC_REQUIRE(\[AC_USE_SYSTEM_EXTENSIONS\])/dnl AC_REQUIRE([AC_USE_SYSTEM_EXTENSIONS])/' m4/libopenflow.m4
sed -i 's/$(MKDIR_P)/mkdir -p/g' lib/automake.mk

%build
./boot.sh
%configure --enable-ssl --enable-snat
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
