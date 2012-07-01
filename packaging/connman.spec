Name:           connman
Version:        0.78.4_81
Release:        1
License:        GPLv2
Summary:        Connection Manager
Url:            http://connman.net
Group:          System/Networking
Source0:        %{name}-%{version}.tar.gz
Source1001:     packaging/connman.manifest
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libiptc)
BuildRequires:  pkgconfig(xtables)
Requires:   systemd
Requires(post):   systemd 
Requires(preun):  systemd
Requires(postun): systemd

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%package test
Summary:        Test Scripts for Connection Manager
Group:          Development/Tools
Requires:       %{name} = %{version}-%{release}
Requires:       dbus-python
Requires:       pygobject2
Requires:       python-xml

%description test
Scripts for testing Connman and its functionality


%package devel
Summary:        Development Files for connman
Group:          Development/Tools
Requires:       %{name} = %{version}-%{release}

%description devel
Header files and development files for connman.

%prep
%setup -q


%build
cp %{SOURCE1001} .

./autogen.sh

%configure --enable-threads \
            --enable-tizen-ext \
            --enable-wifi=builtin \
%if 0%{?enable_ofono}
            --enable-ofono=builtin \
            --enable-telephony=no \
%endif
            --enable-test \
            --with-systemdunitdir=%{_libdir}/systemd/system


make %{?_smp_mflags}

%install
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/network.target.wants
ln -s ../connman.service %{buildroot}%{_libdir}/systemd/system/network.target.wants/connman.service


mkdir -p %{buildroot}%{_localstatedir}/lib/connman
cp resources/var/lib/connman/settings %{buildroot}%{_localstatedir}/lib/connman/settings
mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cp resources/usr/share/dbus-1/services/net.connman.service %{buildroot}%{_datadir}/dbus-1/services/net.connman.service
mkdir -p %{buildroot}%{_sysconfdir}/connman
cp src/main.conf %{buildroot}%{_sysconfdir}/connman/main.conf

# FIXME: All of below has to go when systemd lands
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/init.d
cp resources/etc/rc.d/init.d/connman %{buildroot}%{_sysconfdir}/rc.d/init.d/connman
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc3.d
ln -s ../init.d/connman %{buildroot}%{_sysconfdir}/rc.d/rc3.d/S61connman
mkdir -p %{buildroot}%{_sysconfdir}/rc.d/rc5.d
ln -s ../init.d/connman %{buildroot}%{_sysconfdir}/rc.d/rc5.d/S61connman

rm %{buildroot}%{_sysconfdir}/dbus-1/system.d/*.conf
mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d/
cp src/connman.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/

%post
systemctl daemon-reload
systemctl restart connman.service
 
%preun
systemctl stop connman.service
 
%postun
systemctl daemon-reload

%files
%manifest connman.manifest
%{_sbindir}/*
%attr(600,root,root) %{_localstatedir}/lib/connman/settings
%{_libdir}/connman/plugins/*.so
%{_datadir}/dbus-1/services/*
%{_sysconfdir}/dbus-1/system.d/*
%{_sysconfdir}/connman/main.conf
%{_sysconfdir}/dbus-1/system.d/*.conf
%{_sysconfdir}/rc.d/init.d/connman
%{_sysconfdir}/rc.d/rc3.d/S61connman
%{_sysconfdir}/rc.d/rc5.d/S61connman
%{_libdir}/systemd/system/connman.service
%{_libdir}/systemd/system/network.target.wants/connman.service

%files test
%{_libdir}/%{name}/test/*


%files devel
%{_includedir}/*
%{_libdir}/pkgconfig/*.pc
