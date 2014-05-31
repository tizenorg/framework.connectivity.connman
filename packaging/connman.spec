Name:           connman
Version:        1.3_22
Release:        1
License:        GPLv2
Summary:        Connection Manager
Url:            http://connman.net
Group:          System/Networking
Source0:        %{name}-%{version}.tar.gz

%if "%{_repository}" == "wearable"
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(xtables)
BuildRequires:	pkgconfig(libsmack)
Requires:		systemd
Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.
%else
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(libiptc)
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libsmack)
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
%endif

%prep
%setup -q


%build
%if "%{_repository}" == "wearable"
cd wearable
CFLAGS+=" -Wall -Werror -O2 -D_FORTIFY_SOURCE=2"
./bootstrap
%else
cd mobile
CFLAGS+=" -DTIZEN_EXT -lsmack"
./bootstrap
%endif

%if "%{_repository}" == "wearable"
%configure --prefix=/usr \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --enable-tizen-ext \
            --enable-tizen-rtc-timer \
            --enable-threads \
            --enable-ethernet \
            --enable-wifi=builtin \
            --enable-bluetooth \
            --enable-telephony=builtin \
            --enable-loopback \
            --disable-client \
            --disable-ofono \
            --disable-tools \
            --disable-wispr \
            --disable-linklocaladdr \
            --with-systemdunitdir=%{_libdir}/systemd/system
%else
%configure \
            --sysconfdir=/etc \
            --enable-threads \
            --enable-wifi=builtin \
            --enable-test \
	    --enable-loopback \
	    --enable-ethernet \
	    --disable-linklocaladdr \
	    --sysconfdir=/opt/etc \
            --with-systemdunitdir=%{_libdir}/systemd/system
%endif

make %{?_smp_mflags}

%install
%if "%{_repository}" == "wearable"
cd wearable
%make_install

#Systemd service file
mkdir -p %{buildroot}%{_libdir}/systemd/system/
cp src/connman.service %{buildroot}%{_libdir}/systemd/system/connman.service
mkdir -p %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/
ln -s ../connman.service %{buildroot}%{_libdir}/systemd/system/multi-user.target.wants/connman.service

mkdir -p %{buildroot}%{_localstatedir}/lib/connman
cp resources/var/lib/connman/settings %{buildroot}%{_localstatedir}/lib/connman/settings
mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cp resources/usr/share/dbus-1/services/net.connman.service %{buildroot}%{_datadir}/dbus-1/services/net.connman.service
mkdir -p %{buildroot}%{_sysconfdir}/connman
cp src/main.conf %{buildroot}%{_sysconfdir}/connman/main.conf

rm -rf %{buildroot}%{_includedir}
rm -rf %{buildroot}%{_libdir}/pkgconfig/*.pc
rm %{buildroot}%{_sysconfdir}/dbus-1/system.d/*.conf

mkdir -p %{buildroot}%{_sbindir}/
cp resources/usr/sbin/connman.service %{buildroot}%{_sbindir}/connman.service

#DBus DAC (manifest enables DBus SMACK)
#mkdir -p %{buildroot}%{_sysconfdir}/dbus-1/system.d/
#cp src/connman.conf %{buildroot}%{_sysconfdir}/dbus-1/system.d/

#License
mkdir -p %{buildroot}%{_datadir}/license
cp COPYING %{buildroot}%{_datadir}/license/connman

%else
cd mobile
%make_install

mkdir -p %{buildroot}%{_libdir}/systemd/system/network.target.wants
ln -s ../connman.service %{buildroot}%{_libdir}/systemd/system/network.target.wants/connman.service


mkdir -p %{buildroot}%{_localstatedir}/lib/connman
cp resources/var/lib/connman/settings %{buildroot}%{_localstatedir}/lib/connman/settings
mkdir -p %{buildroot}%{_datadir}/dbus-1/services
cp resources/usr/share/dbus-1/services/net.connman.service %{buildroot}%{_datadir}/dbus-1/services/net.connman.service
mkdir -p %{buildroot}/opt/etc/connman
cp src/main.conf %{buildroot}/opt/etc/connman/main.conf

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

#License
mkdir -p %{buildroot}%{_datadir}/license
cp COPYING %{buildroot}%{_datadir}/license/connman
%endif

%if "%{_repository}" == "mobile"
%post
systemctl daemon-reload
systemctl restart connman.service

%preun
systemctl stop connman.service

%postun
systemctl daemon-reload
%endif

%if "%{_repository}" == "wearable"
%files
%manifest wearable/connman.manifest
%attr(500,root,root) %{_sbindir}/*
%attr(600,root,root) %{_localstatedir}/lib/connman/settings
#All of builtin plugins
#%{_libdir}/connman/plugins/*.so
%attr(644,root,root) %{_datadir}/dbus-1/services/*
#DBus DAC
#%attr(644,root,root) %{_sysconfdir}/dbus-1/system.d/*
%attr(644,root,root) %{_sysconfdir}/connman/main.conf
%attr(644,root,root) %{_libdir}/systemd/system/connman.service
%attr(644,root,root) %{_libdir}/systemd/system/multi-user.target.wants/connman.service
%{_datadir}/license/connman

#%files test
#%{_libdir}/%{name}/test/*
%else
%files
%manifest mobile/connman.manifest
%{_sbindir}/*
%attr(600,root,root) %{_localstatedir}/lib/connman/settings
%{_libdir}/connman/plugins/*.so
%{_datadir}/dbus-1/services/*
%{_sysconfdir}/dbus-1/system.d/*
/opt/etc/connman/main.conf
%{_sysconfdir}/dbus-1/system.d/*.conf
%{_sysconfdir}/rc.d/init.d/connman
%{_sysconfdir}/rc.d/rc3.d/S61connman
%{_sysconfdir}/rc.d/rc5.d/S61connman
%{_libdir}/systemd/system/connman.service
%{_libdir}/systemd/system/network.target.wants/connman.service
%{_datadir}/license/connman

%files test
%{_libdir}/%{name}/test/*

%files devel
%{_includedir}/*
%{_libdir}/pkgconfig/*.pc
%endif
