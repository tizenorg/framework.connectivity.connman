Name:       connman
Summary:    Connection Manager
Version:    0.77.2
Release:    1
Group:      System/Networking
License:    GPLv2
URL:        http://connman.net/
Source0:    http://www.kernel.org/pub/linux/network/connman/connman-%{version}.tar.gz
Patch0:     connman_args.patch
Requires:   wpa_supplicant >= 0.7.1
BuildRequires:  pkgconfig(libiptc)
BuildRequires:  pkgconfig(xtables)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libudev) >= 145


%description
Connection Manager provides a daemon for managing Internet connections
within embedded devices running the Linux operating system.



%package devel
Summary:    Development files for Connection Manager
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
connman-devel contains development files for use with connman.

%package test
Summary:    Test Scripts for Connection Manager  
Group:      Development/Tools  
Requires:   %{name} = %{version}-%{release}  
Requires:   dbus-python  
Requires:   pygobject2  
  
%description test  
Scripts for testing Connman and its functionality  

%prep
%setup -q -n %{name}-%{version}
%patch0 -p1

%build
./bootstrap
%configure \
                --localstatedir=/var \
%ifarch %ix86
		--enable-ethernet \
		--enable-wifi \
%endif
                --enable-threads \
                --enable-sonet \
                --enable-tizen-ext \
                --enable-alwayson \
		--enable-test

make %{?jobs:-j%jobs}

%install
%make_install

mkdir -p %{buildroot}/etc/rc.d/init.d
cp etc/rc.d/init.d/connman %{buildroot}/etc/rc.d/init.d/connman

%post

ln -sf ../init.d/connman /etc/rc.d/rc3.d/S61connman
ln -sf ../init.d/connman /etc/rc.d/rc5.d/S61connman

%files
%doc COPYING
%{_sbindir}/*
/usr/lib/connman/plugins/*.so
/etc/rc.d/init.d/connman
%config %{_sysconfdir}/dbus-1/system.d/*.conf


%files devel
%{_includedir}/%{name}/*.h
%{_libdir}/pkgconfig/*.pc

%files test  
%defattr(-,root,root,-)  
%{_libdir}/%{name}/test/* 
