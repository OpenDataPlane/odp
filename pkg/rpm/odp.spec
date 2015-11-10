# Copyright (c) 2015, Linaro Limited
# All rights reserved.
#
# SPDX-License-Identifier:     BSD-3-Clause

Name: opendataplane
Version: Dummy that will be replaced!
Release: 1
Packager: anders.roxell@linaro.org
URL: http://opendataplane.org
Source: %{name}-%{version}.tar.gz
Summary: OpenDataPlane Reference implementation
Group: System Environment/Libraries
License: BSD-3-Clause
BuildRequires: automake
BuildRequires: autoconf
BuildRequires: libtool
BuildRequires: libtoolize
BuildRequires: libssl-devel
BuildRequires: doxygen
BuildRequires: asciidoc
BuildRequires: source-highlight
BuildRequires: texlive-collection-fontsextra
BuildRequires: texlive-collection-latexextra

%description
ODP's reference implementation includes header files and a library
More libraries are available as extensions in other packages.

%package devel
Summary: OpenDataPlane Reference implementation
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
ODP devel is a set of headers, a library and example files.
This is a reference implementation.

%package doc
Summary: OpenDataPlane Reference documentation
BuildArch: noarch

%description doc
ODP doc is divided in two parts: API details in doxygen HTML format
and guides in HTMLformats.

%prep
%autosetup -n %{name}-%{version}

%configure
%make_install

%files
%{_datadir}/*
%{_bindir}/*
%{_libdir}/*

%files devel
%{_includedir}/*
%{_libdir}/

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
%changelog
* Tue Nov 10 2015 - anders.roxell (at) linaro.org
- Initial rpm release, ODP release v1.4
