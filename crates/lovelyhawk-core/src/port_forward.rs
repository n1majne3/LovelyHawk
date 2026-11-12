//! Local port forwarding over SSH `direct-tcpip` channels.
//!
//! The backend binds a loopback listener per forward; every accepted socket
//! becomes one `direct-tcpip` channel on the bound session. Destinations are
//! confined to addresses the target itself reports as listeners: loopback is
//! always allowed, anything else must appear in the `/proc/net/tcp{,6}`
//! LISTEN table read at plan time. Nothing here ever writes to the target.

use std::net::IpAddr;

use crate::error::{CoreError, CoreResult};

/// Forwards one binding may hold open at once.
pub const MAX_FORWARDS_PER_BINDING: usize = 8;
/// Sockets one forward pumps at once; further accepts wait for a slot.
pub const MAX_FORWARD_CONNECTIONS: usize = 32;

/// The fixed, core-owned read of the target's LISTEN table. No user input
/// ever reaches this command.
pub const LISTEN_TABLE_COMMAND: &str = "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null";

/// A destination the operator asked to reach through the forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardDestination {
    pub host: IpAddr,
    pub port: u16,
}

/// Validates a requested local port: `0` means the OS picks an ephemeral
/// one, anything else must be an unprivileged port.
pub fn validate_local_port(port: u16) -> CoreResult<u16> {
    if port != 0 && port < 1024 {
        return Err(CoreError::validation(
            "local forward port",
            "local forward ports are 1024-65535, or 0 for an ephemeral port",
        ));
    }
    Ok(port)
}

/// Parses one destination host literal. Only IP addresses are accepted:
/// the allowlist is read from the target's own LISTEN table, which names
/// addresses, never names.
pub fn parse_destination_host(host: &str) -> CoreResult<IpAddr> {
    host.trim().parse::<IpAddr>().map_err(|_| {
        CoreError::validation("forward destination", "destination must be an IP address")
    })
}

/// Validates a requested destination port: a forward to port 0 reaches
/// nothing, and u16 already bounds the top of the range.
pub fn validate_destination_port(port: u16) -> CoreResult<u16> {
    if port == 0 {
        return Err(CoreError::validation(
            "forward destination",
            "port must be 1-65535",
        ));
    }
    Ok(port)
}

/// Parses a `/proc/net/tcp` or `/proc/net/tcp6` body into `(addr, port)`
/// pairs whose state is LISTEN (`0A`). Malformed lines are skipped; the
/// result is bounded so a hostile /proc read cannot grow memory freely.
pub fn parse_listen_table(text: &str) -> Vec<(IpAddr, u16)> {
    let mut table = Vec::new();
    for line in text.lines() {
        if table.len() >= 65_536 {
            break;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st ... — state 0A is LISTEN.
        if fields.len() < 4 || fields[3] != "0A" {
            continue;
        }
        let mut parts = fields[1].split(':');
        let (Some(addr_hex), Some(port_hex)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(port) = u16::from_str_radix(port_hex, 16).ok() else {
            continue;
        };
        let addr = if addr_hex.len() == 8 {
            // Little-endian IPv4.
            u32::from_str_radix(addr_hex, 16)
                .ok()
                .map(u32::to_be)
                .map(std::net::Ipv4Addr::from)
                .map(IpAddr::V4)
        } else if addr_hex.len() == 32 {
            // Four little-endian u32 words make one IPv6 address.
            let mut bytes = [0u8; 16];
            let mut ok = true;
            for word in 0..4 {
                let start = word * 8;
                match u32::from_str_radix(&addr_hex[start..start + 8], 16) {
                    Ok(value) => {
                        bytes[word * 4..word * 4 + 4].copy_from_slice(&value.to_be_bytes())
                    }
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
            } else {
                None
            }
        } else {
            continue;
        };
        if let Some(addr) = addr {
            table.push((addr, port));
        }
    }
    table
}

/// Whether the target's LISTEN table permits this destination. Loopback is
/// always permitted (the target itself reaches it); any other address must
/// be a listener the target reported — either exactly, or through a
/// wildcard listener covering the port.
pub fn destination_allowed(dest: &ForwardDestination, table: &[(IpAddr, u16)]) -> bool {
    if dest.port == 0 {
        return false;
    }
    if dest.host.is_loopback() {
        return true;
    }
    let wildcard = match dest.host {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    };
    table
        .iter()
        .any(|(addr, port)| *port == dest.port && (*addr == dest.host || *addr == wildcard))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
        \x20 0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n\
        \x20 1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346\n\
        \x20 2: 0100007F:0035 0200007F:E240 01 00000000:00000000 00:00000000 00000000     0        0 12347\n\
        \x20 3: 00000000000000000000000000000000:8B8C 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12348\n";

    #[test]
    fn parses_listen_rows_and_skips_other_states() {
        let table = parse_listen_table(TABLE);
        assert!(table.contains(&(IpAddr::V4("127.0.0.1".parse().unwrap()), 8080)));
        assert!(table.contains(&(IpAddr::V4("0.0.0.0".parse().unwrap()), 22)));
        // State 01 (ESTABLISHED) is not a listener.
        assert!(!table.iter().any(|(_, port)| *port == 53));
        assert!(table.contains(&(IpAddr::V6("::".parse().unwrap()), 0x8B8C)));
    }

    #[test]
    fn loopback_is_always_allowed_and_table_governs_the_rest() {
        let table = parse_listen_table(TABLE);
        let loopback = ForwardDestination {
            host: "127.0.0.1".parse().unwrap(),
            port: 8080,
        };
        assert!(destination_allowed(&loopback, &table));
        let v6loop = ForwardDestination {
            host: "::1".parse().unwrap(),
            port: 9,
        };
        assert!(destination_allowed(&v6loop, &table));
        // Wildcard LISTEN covers a non-loopback destination on the same port.
        let any = ForwardDestination {
            host: "10.0.0.5".parse().unwrap(),
            port: 22,
        };
        assert!(destination_allowed(&any, &table));
        // No listener on this port: refused.
        let denied = ForwardDestination {
            host: "10.0.0.5".parse().unwrap(),
            port: 4444,
        };
        assert!(!destination_allowed(&denied, &table));
        // Port 0 is never a destination.
        let zero = ForwardDestination {
            host: "127.0.0.1".parse().unwrap(),
            port: 0,
        };
        assert!(!destination_allowed(&zero, &table));
    }

    #[test]
    fn local_ports_are_unprivileged_or_ephemeral() {
        assert!(validate_local_port(0).is_ok());
        assert!(validate_local_port(1024).is_ok());
        assert!(validate_local_port(65535).is_ok());
        assert!(validate_local_port(22).is_err());
        assert!(validate_destination_port(1).is_ok());
        assert!(validate_destination_port(65535).is_ok());
        assert!(validate_destination_port(0).is_err());
    }

    #[test]
    fn malformed_listen_rows_are_skipped_not_panicked() {
        // Short fields, missing ports, non-hex, truncated IPv6, and a row
        // whose local address is empty all fail closed.
        let garbage = "sl local_address rem_address st\n\
            \x20 0: 0100007F 00000000:0000 0A\n\
            \x20 1: ZZZZ:1F90 00000000:0000 0A\n\
            \x20 2: 0100007F001F:1F90 00000000:0000 0A\n\
            \x20 3: :1F90 00000000:0000 0A\n\
            \x20 4: 0100007F:XYZQ 00000000:0000 0A\n\
            \x20 5: 0000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A\n\
            \x20 6: 0100007F:10000 00000000:0000 0A\n";
        let table = parse_listen_table(garbage);
        assert!(table.is_empty());
        // Port 0x10000 overflows u16 and must not wrap to 0.
        let wrap = "  0: 0100007F:10000 00000000:0000 0A 0 0 0 0 0 0\n";
        assert!(parse_listen_table(wrap).is_empty());
    }

    #[test]
    fn destination_hosts_are_ip_literals() {
        assert_eq!(
            parse_destination_host(" 127.0.0.1 ").unwrap(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            parse_destination_host("::1").unwrap(),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert!(parse_destination_host("example.com").is_err());
        assert!(parse_destination_host("127.0.0.1:80").is_err());
        assert!(parse_destination_host("$(reboot)").is_err());
    }
}
