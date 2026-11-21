//! Install the tunnel's learned prefixes into the host route table.
//!
//! The child already knows which peer owns which prefix; without a kernel route
//! the host never sends the packet to the tun in the first place. This module
//! keeps that table in step with the catalog: add what appeared, remove what
//! left, and report what the kernel actually accepted.
//!
//! Two rules keep this from becoming a second, silent control plane:
//!
//! - only prefixes learned from the catalog are touched;
//! - a route is only removed when this process added it, so a hand-written
//!   route on the same interface survives a tunnel restart.
//!
//! The commands are fixed (`route`/`ip`), arguments are passed as separate
//! argv entries, and no shell is involved.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::process::Command;

use crate::Route;

/// One destination prefix. Kept as address + length so two spellings of the
/// same network cannot become two kernel routes.
pub(crate) type Prefix = (IpAddr, u8);

#[derive(Default)]
pub struct KernelRoutes {
    tun: String,
    installed: BTreeSet<Prefix>,
    error: Option<String>,
}

impl KernelRoutes {
    pub fn new(tun: &str) -> Self {
        Self {
            tun: tun.to_owned(),
            installed: BTreeSet::new(),
            error: None,
        }
    }

    /// Prefixes currently installed by this process, in stable order.
    pub fn installed(&self) -> Vec<String> {
        self.installed
            .iter()
            .map(|(addr, len)| format!("{addr}/{len}"))
            .collect()
    }

    /// The last reconcile error, if any. A successful reconcile clears it.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Add newly learned prefixes and remove departed ones. Returns the first
    /// hard failure while still applying the rest: one bad prefix must not
    /// leave every other peer unreachable.
    pub fn reconcile(&mut self, routes: &[Route]) -> Result<(), String> {
        let desired: BTreeSet<Prefix> =
            routes.iter().map(|route| (route.addr, route.len)).collect();

        let mut first_error = None;
        for prefix in self
            .installed
            .difference(&desired)
            .copied()
            .collect::<Vec<_>>()
        {
            // A route that is already gone is not an error: the kernel may have
            // removed the interface, or a previous cleanup may have run.
            let _ = run(delete_command(prefix, &self.tun));
            self.installed.remove(&prefix);
        }
        for prefix in desired
            .difference(&self.installed)
            .copied()
            .collect::<Vec<_>>()
        {
            match run(add_command(prefix, &self.tun)) {
                Ok(()) => {
                    self.installed.insert(prefix);
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        self.error = first_error.clone();
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Remove every route this process installed. Called on a clean shutdown and
    /// by the signal path; a killed process leaves routes for the next start to
    /// clean up from its status document.
    pub fn clear(&mut self) {
        for prefix in std::mem::take(&mut self.installed) {
            let _ = run(delete_command(prefix, &self.tun));
        }
    }
}

impl Drop for KernelRoutes {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Remove routes a previous process reported installing on this same tun.
///
/// The status document is the only durable record of what the child added. It
/// is read before the new table is installed so a crash cannot accumulate
/// routes forever. A missing, stale or different-tun document removes nothing.
pub fn clear_previous(status_path: Option<&std::path::Path>, tun: &str) {
    let Some(path) = status_path else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    if value.get("tun").and_then(|value| value.as_str()) != Some(tun) {
        return;
    }
    let Some(prefixes) = value
        .get("kernel_routes")
        .and_then(|value| value.as_array())
    else {
        return;
    };
    for prefix in prefixes.iter().filter_map(|value| value.as_str()) {
        let Ok((addr, len)) = parse_prefix(prefix) else {
            continue;
        };
        let _ = run(delete_command((addr, len), tun));
    }
}

fn parse_prefix(value: &str) -> Result<Prefix, ()> {
    let (addr, len) = value.split_once('/').ok_or(())?;
    let addr = addr.parse::<IpAddr>().map_err(|_| ())?;
    let len = len.parse::<u8>().map_err(|_| ())?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if len > max {
        return Err(());
    }
    Ok((addr, len))
}

#[derive(Debug)]
struct Invocation {
    program: &'static str,
    args: Vec<String>,
}

fn add_command(prefix: Prefix, tun: &str) -> Invocation {
    let (addr, len) = prefix;
    let prefix = format!("{addr}/{len}");
    #[cfg(target_os = "macos")]
    {
        let family = if addr.is_ipv4() { "-inet" } else { "-inet6" };
        Invocation {
            program: "/sbin/route",
            args: vec![
                "-n".into(),
                "add".into(),
                family.into(),
                prefix,
                "-interface".into(),
                tun.into(),
            ],
        }
    }
    #[cfg(target_os = "linux")]
    {
        let family = if addr.is_ipv4() { "-4" } else { "-6" };
        Invocation {
            program: "ip",
            args: vec![
                family.into(),
                "route".into(),
                "replace".into(),
                prefix,
                "dev".into(),
                tun.into(),
            ],
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Invocation {
            program: "true",
            args: vec![prefix, tun.to_owned()],
        }
    }
}

fn delete_command(prefix: Prefix, tun: &str) -> Invocation {
    let (addr, len) = prefix;
    let prefix = format!("{addr}/{len}");
    #[cfg(target_os = "macos")]
    {
        let family = if addr.is_ipv4() { "-inet" } else { "-inet6" };
        Invocation {
            program: "/sbin/route",
            args: vec![
                "-n".into(),
                "delete".into(),
                family.into(),
                prefix,
                "-interface".into(),
                tun.into(),
            ],
        }
    }
    #[cfg(target_os = "linux")]
    {
        let family = if addr.is_ipv4() { "-4" } else { "-6" };
        Invocation {
            program: "ip",
            args: vec![
                family.into(),
                "route".into(),
                "del".into(),
                prefix,
                "dev".into(),
                tun.into(),
            ],
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Invocation {
            program: "true",
            args: vec![prefix, tun.to_owned()],
        }
    }
}

fn run(invocation: Invocation) -> Result<(), String> {
    let output = Command::new(invocation.program)
        .args(&invocation.args)
        .output()
        .map_err(|error| format!("{}: {error}", invocation.program))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    Err(if detail.is_empty() {
        format!("{} exited {}", invocation.program, output.status)
    } else {
        format!("{}: {detail}", invocation.program)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_round_trips_through_status_text() {
        let prefix = ("fd7a:115c:a1f0::7".parse().unwrap(), 128);
        assert_eq!(parse_prefix("fd7a:115c:a1f0::7/128"), Ok(prefix));
        assert!(parse_prefix("not-a-prefix").is_err());
        assert!(parse_prefix("10.0.0.1/33").is_err());
    }

    #[test]
    fn a_catalog_change_only_touches_learned_prefixes() {
        // This exercises the set arithmetic without invoking the host. The
        // command builders are tested below; the kernel call itself is the only
        // part that needs a live interface.
        let one: Prefix = ("10.42.0.7".parse().unwrap(), 32);
        let two: Prefix = ("10.42.0.8".parse().unwrap(), 32);
        let installed: BTreeSet<Prefix> = [one].into_iter().collect();
        let desired: BTreeSet<Prefix> = [two].into_iter().collect();
        let removed: Vec<_> = installed.difference(&desired).copied().collect();
        let added: Vec<_> = desired.difference(&installed).copied().collect();
        assert_eq!(removed, vec![one]);
        assert_eq!(added, vec![two]);
    }

    #[test]
    fn route_commands_name_the_tun_and_the_prefix() {
        let v4 = ("10.42.0.7".parse().unwrap(), 32);
        let v6 = ("fd7a:115c:a1f0::7".parse().unwrap(), 128);
        for (command, prefix) in [
            (add_command(v4, "utun220"), "10.42.0.7/32"),
            (delete_command(v4, "utun220"), "10.42.0.7/32"),
            (add_command(v6, "utun220"), "fd7a:115c:a1f0::7/128"),
            (delete_command(v6, "utun220"), "fd7a:115c:a1f0::7/128"),
        ] {
            assert!(
                command.args.iter().any(|arg| arg == "utun220"),
                "the interface must be explicit: {command:?}"
            );
            assert!(
                command.args.iter().any(|arg| arg == prefix),
                "the prefix must be explicit: {command:?}"
            );
        }
    }
}
