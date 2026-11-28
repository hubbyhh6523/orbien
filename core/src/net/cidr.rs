//! A minimal CIDR matcher (moved from the server access policy, #17, so
//! the client-side SOCKS5 destination filter can reuse it).
//!
//! `parse` accepts `10.0.0.0/8` or a bare IP (treated as /32 or /128).
//! `contains` matches same-family addresses only; normalize IPv4-mapped
//! IPv6 addresses with `to_ipv4_mapped` before calling it when the input
//! may be mapped.
use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some((ip, pref)) = s.split_once('/') {
            let addr: IpAddr = ip.parse()?;
            let prefix: u8 = pref.parse()?;
            let max = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                bail!("CIDR prefix {prefix} too large for {addr}");
            }
            Ok(Self { addr, prefix })
        } else {
            let addr: IpAddr = s.parse()?;
            let prefix = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Self { addr, prefix })
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => ipv4_in_cidr(net, self.prefix, ip),
            (IpAddr::V6(net), IpAddr::V6(ip)) => ipv6_in_cidr(net, self.prefix, ip),
            _ => false,
        }
    }
}

fn ipv4_in_cidr(net: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

fn ipv6_in_cidr(net: Ipv6Addr, prefix: u8, ip: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    let net_o = net.octets();
    let ip_o = ip.octets();
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if net_o[..full] != ip_o[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    (net_o[full] & mask) == (ip_o[full] & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bare_ip_is_single_host() {
        let c = Cidr::parse("10.1.2.3").unwrap();
        assert!(c.contains(v4("10.1.2.3")));
        assert!(!c.contains(v4("10.1.2.4")));
    }

    #[test]
    fn v4_prefix_match() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(v4("10.255.0.1")));
        assert!(!c.contains(v4("11.0.0.1")));
    }

    #[test]
    fn v6_prefix_match() {
        let c = Cidr::parse("fd00::/8").unwrap();
        assert!(c.contains("fd12::1".parse().unwrap()));
        assert!(!c.contains("fe00::1".parse().unwrap()));
    }

    #[test]
    fn mismatched_families_do_not_match() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(!c.contains("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn oversized_prefix_rejected() {
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("not-an-ip").is_err());
    }
}
