use std::net::{IpAddr, Ipv4Addr};

pub struct Addresses {
    pub lan: Option<Ipv4Addr>,
    pub tailscale: Option<Ipv4Addr>,
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
            .or(self.lan)
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    }

    fn from_interfaces(interfaces: &[if_addrs::Interface], installed: bool) -> Self {
        let is_tailscale = |interface: &&if_addrs::Interface| {
            interface.name.to_ascii_lowercase().starts_with("tailscale")
        };
        let tailscale_interfaces: Vec<_> = interfaces.iter().filter(is_tailscale).collect();
        let tailscale = tailscale_interfaces.iter().find_map(|interface| {
            let IpAddr::V4(ip) = interface.ip() else {
                return None;
            };
            (interface.is_oper_up() && !ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
        });
        Self {
            lan: preferred_lan_address(interfaces),
            tailscale,
            tailscale_installed: installed || !tailscale_interfaces.is_empty(),
        }
    }
}

fn preferred_lan_address(interfaces: &[if_addrs::Interface]) -> Option<Ipv4Addr> {
    interfaces
        .iter()
        .filter(|interface| interface.is_oper_up() && !interface.is_p2p())
        .filter_map(|interface| {
            let IpAddr::V4(ip) = interface.ip() else {
                return None;
            };
            let name = interface.name.to_ascii_lowercase();
            // A VPN default route or a VM/container bridge is usually not the
            // network shared with the phone. These addresses remain usable as
            // manual overrides in the pairing page.
            let virtual_interface = [
                "docker",
                "br-",
                "veth",
                "virbr",
                "vmnet",
                "vmware",
                "vboxnet",
                "virtualbox",
                "tailscale",
                "tun",
                "tap",
                "utun",
                "wg",
            ]
            .iter()
            .any(|prefix| name.starts_with(prefix));
            if virtual_interface
                || ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
            {
                return None;
            }
            Some((ip, interface.index.unwrap_or(u32::MAX)))
        })
        .min_by_key(|(ip, index)| (!ip.is_private(), *index, *ip))
        .map(|(ip, _)| ip)
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
        assert_eq!(
            preferred_lan_address(&interfaces),
            Some([192, 168, 4, 2].into())
        );
        let addresses = Addresses::from_interfaces(&interfaces, false);
        assert_eq!(addresses.lan, Some([192, 168, 4, 2].into()));
        assert_eq!(addresses.tailscale, Some([100, 116, 134, 128].into()));
        assert!(addresses.tailscale_installed);
        assert_eq!(addresses.preferred_host(), "100.116.134.128");
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
        assert_eq!(preferred_lan_address(&interfaces), None);
        assert!(
            Addresses::from_interfaces(&interfaces, false)
                .preferred_host()
                .is_empty()
        );
    }

    #[test]
    fn installed_but_inactive_tailscale_falls_back_to_lan() {
        let mut tailscale = interface("Tailscale", [100, 64, 0, 5]);
        tailscale.oper_status = if_addrs::IfOperStatus::Down;
        let interfaces = [tailscale, interface("wlan0", [192, 168, 1, 10])];
        let addresses = Addresses::from_interfaces(&interfaces, true);
        assert!(addresses.tailscale_installed);
        assert_eq!(addresses.tailscale, None);
        assert_eq!(addresses.preferred_host(), "192.168.1.10");
    }
}
