Name:           connman
Version:        1.29.37
Release:        1
License:        GPL-2.0+
Summary:        Connection Manager
Url:            http://connman.net
Group:          Network & Connectivity/Connection Management
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libiptc)
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libsmack)
BuildRequires:  readline-devel
%systemd_requires
Requires:       iptables
Requires:         systemd
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.


%package test
Summary:        Test Scripts for Connection Manager
Group:          Development/Tools
Requires:       %{name} = %{version}
Requires:       dbus-python
Requires:       pygobject
Requires:       python-xml

%description test
Scripts for testing Connman and its functionality

%package devel
Summary:        Development Files for connman
Group:          Development/Tools
Requires:       %{name} = %{version}

%description devel
Header files and development files for connman.

%prep
%setup -q


%build
CFLAGS+=" -DTIZEN_EXT -lsmack -Werror"
%if "%{?tizen_profile_name}" == "tv"
CFLAGS+=" -DTIZEN_TV_EXT"
%endif

chmod +x bootstrap
./bootstrap
%configure \
            --sysconfdir=/etc \
            --enable-client \
            --enable-pacrunner \
            --enable-wifi=builtin \
%if 0%{?enable_connman_features}
            %connman_features \
%endif
            --disable-ofono \
            --enable-telephony=builtin \
            --enable-test \
			--enable-loopback \
			--enable-ethernet \
            --with-systemdunitdir=%{_libdir}/systemd/system \
            --enable-pie

make %{?_smp_mflags}

%install
%make_install

#Systemd service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/
%if "%{?_lib}" == "lib64"
mkdir -p %{buildroot}%{_unitdir}
%endif

%if "%{?tizen_profile_name}" == "tv"
cp src/connman_tv.service %{buildroot}%{_libdir}/systemd/system/connman.service
%else
cp src/connman.service %{buildroot}%{_libdir}/systemd/system/connman.service
%if "%{?_lib}" == "lib64"
cp src/connman.service %{buildroot}%{_unitdir}/connman.service
%endif
%endif

mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants
ln -s ../connman.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/connman.service
%if "%{?_lib}" == "lib64"
mkdir -p %{buildroot}%{_unitdir}/multi-user.target.wants
ln -s ../connman.service %{buildroot}%{_unitdir}/multi-user.target.wants/connman.service
%endif

mkdir -p %{buildroot}/%{_localstatedir}/lib/connman
cp resources/var/lib/connman/settings %{buildroot}/%{_localstatedir}/lib/connman/settings
mkdir -p %{buildroot}%{_datadir}/dbus-1/system-services
cp resources/usr/share/dbus-1/system-services/net.connman.service %{buildroot}%{_datadir}/dbus-1/system-services/net.connman.service
mkdir -p %{buildroot}/etc/connman
cp src/main.conf %{buildroot}/etc/connman/main.conf

rm %{buildroot}%{_sysconfdir}/dbus-1/system.d/*.conf
#mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d/
#cp src/connman.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/

#License
mkdir -p %{buildroot}%{_datadir}/license
cp COPYING %{buildroot}%{_datadir}/license/connman

%post
#systemctl daemon-reload
#systemctl restart connman.service

%preun
#systemctl stop connman.service

%postun
#systemctl daemon-reload

%docs_package

%files
%manifest connman.manifest
%attr(500,root,root) %{_sbindir}/*
%attr(500,root,root) %{_bindir}/connmanctl
%attr(600,root,root) /%{_localstatedir}/lib/connman/settings
#%{_libdir}/connman/plugins/*.so
%attr(644,root,root) %{_datadir}/dbus-1/system-services/*
#%{_datadir}/dbus-1/services/*
#%{_sysconfdir}/dbus-1/system.d/*
%attr(644,root,root) %{_sysconfdir}/connman/main.conf
#%{_sysconfdir}/dbus-1/system.d/*.conf
%attr(644,root,root) %{_libdir}/systemd/system/connman.service
%attr(644,root,root) %{_libdir}/systemd/system/multi-user.target.wants/connman.service
%if "%{?_lib}" == "lib64"
%attr(644,root,root) %{_unitdir}/connman.service
%attr(644,root,root) %{_unitdir}/multi-user.target.wants/connman.service
%endif
%{_datadir}/license/connman

%files test
%{_libdir}/%{name}/test/*

%files devel
%{_includedir}/*
%{_libdir}/pkgconfig/*.pc


