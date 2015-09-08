Name:		connman
Summary:	Connection Manager
Version:	1.3.313
Release:	1
Group:		System/Network
License:	GPL-2.0+
URL:		http://connman.net
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dbus-1)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(xtables)
BuildRequires:	pkgconfig(libsmack)
BuildRequires:	model-build-features
Requires:		systemd
Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%prep
%setup -q


%build
CFLAGS+=" -Wall -Werror -O2 -D_FORTIFY_SOURCE=2"

./bootstrap

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
            --with-systemdunitdir=%{_libdir}/systemd/system \
            --enable-pie

make %{?_smp_mflags}


%install
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

%post
#systemctl daemon-reload
#systemctl restart connman.service

%preun
#systemctl stop connman.service

%postun
#systemctl daemon-reload


%files
%manifest connman.manifest
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
