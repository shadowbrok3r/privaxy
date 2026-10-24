use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, PartialEq, Eq)]
pub struct InterfaceAddress {
    pub interface: String,
    pub ip: Ipv4Addr,
}

pub struct Addresses {
    pub lan: Vec<InterfaceAddress>,
    pub tailscale: Vec<InterfaceAddress>,
    pub other: Vec<InterfaceAddress>,
    pub tailscale_installed: bool,
}

impl Addresses {
    pub fn detect() -> Self {
        let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
        let executable = if cfg!(windows) {
            "tailscale.exe"
        } else {
            "tailscale"
        };
        let installed = std::env::var_os("PATH").is_some_and(|paths| {
            std::env::split_paths(&paths).any(|path| path.join(executable).is_file())
        });
        Self::from_interfaces(&interfaces, installed)
    }

    pub fn preferred_host(&self) -> String {
        self.tailscale
            .first()
            .or_else(|| self.lan.first())
            .map(|address| address.ip.to_string())
            .unwrap_or_default()
    }

    fn from_interfaces(interfaces: &[if_addrs::Interface], installed: bool) -> Self {
        let mut addresses = Self {
            lan: Vec::new(),
            tailscale: Vec::new(),
            other: Vec::new(),
            tailscale_installed: installed,
        };
        // Keep every assigned address, including aliases on the same interface.
        // Ordering only chooses a default; it must not hide Wi-Fi behind Ethernet.
        let mut active: Vec<_> = interfaces
            .iter()
            .filter_map(|interface| {
                let name = interface.name.to_ascii_lowercase();
                addresses.tailscale_installed |= name.starts_with("tailscale");
                let IpAddr::V4(ip) = interface.ip() else {
                    return None;
                };
                (interface.is_oper_up()
                    && !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    && !ip.is_broadcast())
                .then_some((interface, ip, name))
            })
            .collect();
        active.sort_by_key(|(interface, ip, _)| {
            (
                !ip.is_private(),
                interface.index.unwrap_or(u32::MAX),
                *ip,
                &interface.name,
            )
        });
        for (interface, ip, name) in active {
            let virtual_interface = [
                "docker",
                "br-",
                "veth",
                "virbr",
                "vmnet",
                "vmware",
                "vboxnet",
                "virtualbox",
                "tun",
                "tap",
                "utun",
                "wg",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix));
            let list = if name.starts_with("tailscale") {
                &mut addresses.tailscale
            } else if virtual_interface || interface.is_p2p() || ip.is_link_local() {
                &mut addresses.other
            } else {
                &mut addresses.lan
            };
            let address = InterfaceAddress {
                interface: interface.name.clone(),
                ip,
            };
            if !list.contains(&address) {
                list.push(address);
            }
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, ip: [u8; 4]) -> if_addrs::Interface {
        if_addrs::Interface {
            name: name.into(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip: ip.into(),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            index: None,
            oper_status: if_addrs::IfOperStatus::Up,
            is_p2p: false,
            #[cfg(windows)]
            adapter_name: name.into(),
        }
    }

    #[test]
    fn selects_lan_over_vpn_vm_and_container_addresses() {
        let interfaces = [
            interface("tailscale0", [100, 116, 134, 128]),
            interface("vmnet8", [172, 16, 163, 1]),
            interface("docker0", [172, 17, 0, 1]),
            interface("br-example", [172, 18, 0, 1]),
            interface("lo", [127, 0, 0, 1]),
            interface("enp9s0", [192, 168, 4, 2]),
        ];
        let addresses = Addresses::from_interfaces(&interfaces, false);
        assert_eq!(addresses.lan.len(), 1);
        assert_eq!(addresses.lan[0].ip, Ipv4Addr::new(192, 168, 4, 2));
        assert_eq!(addresses.tailscale[0].ip, Ipv4Addr::new(100, 116, 134, 128));
        assert_eq!(addresses.other.len(), 3);
        assert!(addresses.tailscale_installed);
        assert_eq!(addresses.preferred_host(), "100.116.134.128");
    }

    #[test]
    fn lists_ethernet_wifi_and_aliases_without_duplicate_entries() {
        let mut ethernet = interface("enp9s0", [192, 168, 4, 2]);
        ethernet.index = Some(2);
        let mut wifi = interface("wlan0", [192, 168, 1, 10]);
        wifi.index = Some(3);
        let mut alias = interface("wlan0", [192, 168, 1, 11]);
        alias.index = Some(3);
        let mut interfaces = vec![wifi.clone(), alias, ethernet, wifi];
        let addresses = Addresses::from_interfaces(&interfaces, false);
        assert_eq!(addresses.lan.len(), 3);
        assert_eq!(addresses.lan[0].interface, "enp9s0");
        assert_eq!(addresses.lan[1].interface, "wlan0");
        assert_eq!(addresses.lan[1].ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(addresses.lan[2].ip, Ipv4Addr::new(192, 168, 1, 11));
        assert_eq!(addresses.preferred_host(), "192.168.4.2");
        interfaces.reverse();
        assert_eq!(
            Addresses::from_interfaces(&interfaces, false).lan,
            addresses.lan
        );
    }

    #[test]
    fn does_not_invent_an_address_when_lan_is_unavailable() {
        let mut disconnected = interface("wlan0", [192, 168, 1, 10]);
        disconnected.oper_status = if_addrs::IfOperStatus::Down;
        let mut vpn = interface("vpn", [10, 0, 0, 5]);
        vpn.is_p2p = true;
        let interfaces = [
            disconnected,
            vpn,
            interface("lo", [127, 0, 0, 1]),
            interface("ethernet", [0, 0, 0, 0]),
            interface("docker0", [172, 17, 0, 1]),
        ];
        let addresses = Addresses::from_interfaces(&interfaces, false);
        assert!(addresses.lan.is_empty());
        assert!(addresses.preferred_host().is_empty());
        assert_eq!(addresses.other.len(), 2);
    }

    #[test]
    fn installed_but_inactive_tailscale_falls_back_to_lan() {
        let mut tailscale = interface("Tailscale", [100, 64, 0, 5]);
        tailscale.oper_status = if_addrs::IfOperStatus::Down;
        let interfaces = [tailscale, interface("wlan0", [192, 168, 1, 10])];
        let addresses = Addresses::from_interfaces(&interfaces, true);
        assert!(addresses.tailscale_installed);
        assert!(addresses.tailscale.is_empty());
        assert_eq!(addresses.preferred_host(), "192.168.1.10");
    }
}
