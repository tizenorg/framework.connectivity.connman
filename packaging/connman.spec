#sbs-git:pkgs/c/connman connman 0.77.2

Name:       connman
Summary:    Connection Manager
Version:    0.77.2_75
Release:    1
Group:      System/Network
License:    GNU General Public License version 2
URL:        http://connman.net
Source0:    %{name}-%{version}.tar.gz
Source1001: packaging/connman.manifest 
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(libiptc)

%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.

%prep
%setup -q


%build
cp %{SOURCE1001} .

./autogen.sh

./configure --prefix=/usr \
            --localstatedir=/var \
            --enable-threads \
            --enable-tizen-ext \
            --enable-wifi=builtin


make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

mkdir -p %{buildroot}/var/lib/connman
cp resources/var/lib/connman/settings %{buildroot}/var/lib/connman/settings
mkdir -p %{buildroot}/usr/share/dbus-1/services
cp resources/usr/share/dbus-1/services/net.connman.service %{buildroot}/usr/share/dbus-1/services/net.connman.service
mkdir -p %{buildroot}/usr/etc/connman
cp src/main.conf %{buildroot}/usr/etc/connman/main.conf
mkdir -p %{buildroot}/etc/rc.d/init.d
cp resources/etc/rc.d/init.d/connman %{buildroot}/etc/rc.d/init.d/connman
mkdir -p %{buildroot}/etc/rc.d/rc3.d
ln -s ../init.d/connman %{buildroot}/etc/rc.d/rc3.d/S61connman
mkdir -p %{buildroot}/etc/rc.d/rc5.d
ln -s ../init.d/connman %{buildroot}/etc/rc.d/rc5.d/S61connman

rm -rf %{buildroot}/usr/include/
rm -rf %{buildroot}/usr/lib/pkgconfig/
rm %{buildroot}/etc/dbus-1/system.d/*.conf

mkdir -p %{buildroot}/usr/etc/dbus-1/system.d/
cp src/connman.conf %{buildroot}/usr/etc/dbus-1/system.d/


%post
#Resource
chmod 600 /var/lib/connman/settings


%files
%manifest connman.manifest
%defattr(-,root,root,-)
#%doc AUTHORS COPYING INSTALL ChangeLog NEWS README
%{_sbindir}/*
%{_var}/lib/connman/settings
%{_libdir}/connman/plugins/*.so
%{_datadir}/dbus-1/services/*
%{_prefix}/etc/dbus-1/system.d/*
%{_prefix}/etc/connman/main.conf
%{_prefix}/etc/dbus-1/system.d/*.conf
%{_sysconfdir}/rc.d/init.d/connman
%{_sysconfdir}/rc.d/rc3.d/S61connman
%{_sysconfdir}/rc.d/rc5.d/S61connman
