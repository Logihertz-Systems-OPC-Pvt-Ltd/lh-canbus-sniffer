Name:           lh-canbus-sniffer
Version:        0.1.0
Release:        1%{?dist}
Summary:        lh-canbus - Bosch CAN 2.0B CRC-15 Cyclic Redundancy Polynomial
License:        Apache-2.0
URL:            https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-canbus-sniffer
Source0:        %{name}-%{version}-src.tar.gz
Packager:       Sameer Tawade <ops@logihertz.com>
BuildArch:      %{_arch}

%description
Memory-safe pure-Rust automotive & industrial SocketCAN real-time packet analyzer, DBC (BO_/SG_) Intel/Motorola bit-field decoder, Bosch CRC-15 verifier, UDS (ISO 14229) IDS, and CAN bus posture auditor.

%prep
%autosetup -n %{name}-0.1.0

%build
# Industrial clean-room build with zero external runtime dependencies

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_docdir}/%{name}
mkdir -p %{buildroot}%{_mandir}/man1

if [ -f bin/lh-canbus ]; then
    install -m 0755 bin/lh-canbus %{buildroot}%{_bindir}/lh-canbus
elif [ -f lh-canbus ]; then
    install -m 0755 lh-canbus %{buildroot}%{_bindir}/lh-canbus
fi

install -m 0644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 0644 SPEC.md %{buildroot}%{_docdir}/%{name}/SPEC.md
install -m 0644 LICENSE %{buildroot}%{_docdir}/%{name}/LICENSE
install -m 0644 NOTICE %{buildroot}%{_docdir}/%{name}/NOTICE

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/SPEC.md
%doc %{_docdir}/%{name}/NOTICE
%license %{_docdir}/%{name}/LICENSE

%changelog
* Mon Nov 16 2026 Sameer Tawade <ops@logihertz.com> - 0.1.0-1
- Initial production release for Logihertz Systems Ecosystem and STRUCT OS.
