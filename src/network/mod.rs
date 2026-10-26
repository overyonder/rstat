//! Network section: time spent waiting on the NAS over SMB, TCP and UDP health, and interfaces.
//! Headline: average number of NAS requests outstanding.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::config::NetworkConfig;
use crate::markup::{Markup, MarkupColors, Severity, WaybarReport};
use crate::procfs_file::{ProcfsFile, read_trimmed};

/// How far back the retransmission ratio looks, so idle intervals don't dominate it.
const RETRANSMISSION_WINDOW: Duration = Duration::from_mins(1);

/// Below this many segments sent in the window a retransmission ratio is too noisy to read as strain.
const RETRANSMISSION_MINIMUM_SEGMENTS: u64 = 500;

/// The SMB client's totals across every command (/proc/fs/cifs/Stats counts time in jiffies, which it
/// documents as 1000 per second).
#[derive(Clone, Copy, Default)]
struct SmbTotals {
    requests:     u64,
    milliseconds: u64,
}

/// /proc/net/dev counters for one interface.
#[derive(Clone, Copy, Default)]
struct InterfaceCounters {
    receive_bytes:   u64,
    receive_packets: u64,
    receive_errors:  u64,
    receive_drops:   u64,
    send_bytes:      u64,
    send_packets:    u64,
    send_errors:     u64,
    send_drops:      u64,
}

/// Cumulative counters at one sample.
#[derive(Clone, Default)]
struct NetworkCounters {
    protocol:   HashMap<String, u64>,  // "Tcp.OutSegs", "TcpExt.ListenOverflows", "Softnet.Dropped", ...
    interfaces: HashMap<String, InterfaceCounters>,
    smb:        SmbTotals,
}

pub(crate) struct NetworkSampler {
    dev:           ProcfsFile,
    snmp:          ProcfsFile,
    netstat:       ProcfsFile,
    softnet:       ProcfsFile,
    route:         ProcfsFile,
    cifs_stats:    Option<ProcfsFile>,
    cifs_debug:    Option<ProcfsFile>,
    previous:      Option<(Instant, NetworkCounters)>,
    retransmits:   VecDeque<(Instant, u64, u64)>,  // Per interval: end, segments sent, retransmitted
    items:         NetworkConfig,
}

impl NetworkSampler {
    pub(crate) fn open(items: NetworkConfig) -> std::io::Result<Self> {
        let open = |path: &str| ProcfsFile::open(path).ok_or_else(|| std::io::Error::other(format!("cannot open {path}")));
        Ok(Self {
            dev:         open("/proc/net/dev")?,
            snmp:        open("/proc/net/snmp")?,
            netstat:     open("/proc/net/netstat")?,
            softnet:     open("/proc/net/softnet_stat")?,
            route:       open("/proc/net/route")?,
            cifs_stats:  ProcfsFile::open("/proc/fs/cifs/Stats"),
            cifs_debug:  ProcfsFile::open("/proc/fs/cifs/DebugData"),
            previous:    None,
            retransmits: VecDeque::new(),
            items,
        })
    }

    fn read_counters(&mut self) -> NetworkCounters {
        let mut protocol = HashMap::new();
        for file in [&mut self.snmp, &mut self.netstat] {
            parse_header_value_pairs(file.read(), &mut protocol);
        }
        let (mut dropped, mut squeezed) = (0, 0);
        for line in self.softnet.read().lines() {
            let fields: Vec<u64> = line.split_whitespace().map(|field| u64::from_str_radix(field, 16).unwrap_or(0)).collect();
            dropped += fields.get(1).copied().unwrap_or(0);
            squeezed += fields.get(2).copied().unwrap_or(0);
        }
        protocol.insert("Softnet.Dropped".to_owned(), dropped);
        protocol.insert("Softnet.TimeSqueeze".to_owned(), squeezed);

        let interfaces = self
            .dev
            .read()
            .lines()
            .skip(2)
            .filter_map(|line| {
                let (name, counters) = line.split_once(':')?;
                let fields: Vec<u64> = counters.split_whitespace().map(|field| field.parse().unwrap_or(0)).collect();
                let field = |index: usize| fields.get(index).copied().unwrap_or(0);
                Some((
                    name.trim().to_owned(),
                    InterfaceCounters {
                        receive_bytes:   field(0),
                        receive_packets: field(1),
                        receive_errors:  field(2),
                        receive_drops:   field(3),
                        send_bytes:      field(8),
                        send_packets:    field(9),
                        send_errors:     field(10),
                        send_drops:      field(11),
                    },
                ))
            })
            .collect();

        let mut smb = SmbTotals::default();
        if let Some(stats) = &mut self.cifs_stats {
            let mut in_table = false;
            for line in stats.read().lines() {
                if line.starts_with("Total time spent processing by command") {
                    in_table = true;
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if in_table && fields.len() == 5 && fields[0].bytes().all(|byte| byte.is_ascii_digit()) {
                    smb.requests += fields[1].parse().unwrap_or(0);
                    smb.milliseconds += fields[2].parse().unwrap_or(0);
                }
            }
        }
        NetworkCounters { protocol, interfaces, smb }
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let now = Instant::now();
        let counters = self.read_counters();
        let Some((previous_time, previous)) = self.previous.replace((now, counters.clone())) else {
            return WaybarReport { alt: "ethernet", ..WaybarReport::collecting_first_sample() };
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();
        let delta = |name: &str| counters.protocol.get(name).copied().unwrap_or(0).saturating_sub(previous.protocol.get(name).copied().unwrap_or(0));
        let per_second = |name: &str| delta(name) as f64 / seconds;

        self.retransmits.push_back((now, delta("Tcp.OutSegs"), delta("Tcp.RetransSegs")));
        while self.retransmits.front().is_some_and(|(end, _, _)| now.duration_since(*end) > RETRANSMISSION_WINDOW) {
            self.retransmits.pop_front();
        }
        let window_start = self.retransmits.front().map_or(previous_time, |(end, _, _)| *end);
        let window_seconds = now.duration_since(window_start).as_secs_f64() + seconds;
        let (sent, retransmitted) = self.retransmits.iter().fold((0, 0), |(sent, retransmitted), (_, s, r)| (sent + s, retransmitted + r));
        let ratio = if sent > 0 { 100.0 * retransmitted as f64 / sent as f64 } else { 0.0 };
        let items = self.items;
        let ratio_severity = if items.retransmissions && sent >= RETRANSMISSION_MINIMUM_SEGMENTS { Severity::of_high(ratio, 2.0, 10.0) } else { Severity::Ok };

        // Time spent on completed NAS requests per second of wall time is the average number of requests
        // outstanding: how many tasks are, on average, waiting on the NAS.
        let nas_requests = counters.smb.requests.saturating_sub(previous.smb.requests) as f64;
        let nas_milliseconds = counters.smb.milliseconds.saturating_sub(previous.smb.milliseconds) as f64;
        let nas_wait = nas_milliseconds / (seconds * 1000.0);
        let nas_latency = if nas_requests > 0.0 { nas_milliseconds / nas_requests } else { 0.0 };
        let active_now = self.cifs_debug.as_mut().map_or(0, |debug| {
            debug.read().lines().find_map(|line| line.strip_prefix("Active VFS Requests:")?.trim().parse().ok()).unwrap_or(0)
        });

        let mut tooltip = Markup::new(colors);
        if items.nas {
            tooltip.heading("NAS (SMB)");
            tooltip
                .line()
                .label("Requests outstanding on average: ")
                .high(nas_wait, &format!("{nas_wait:.2}"), 4.0, 16.0)
                .label(" · active now: ")
                .value(&active_now.to_string());
            tooltip
                .line()
                .label("Requests: ")
                .value(&format!("{:.0}/s", nas_requests / seconds))
                .label(" · average time: ")
                .high(nas_latency, &format!("{nas_latency:.1} ms"), 20.0, 100.0);
        }

        let rate = |name: &str, unit: &str| (per_second(name), format!("{:.0}{unit}", per_second(name)));
        if items.retransmissions || items.connections || items.listen_queue || items.udp_errors || items.kernel_backlog {
            tooltip.heading("TCP and UDP");
        }
        if items.retransmissions {
            tooltip
                .line()
                .label(&format!("Retransmissions over {window_seconds:.0}s: "))
                .toned(ratio_severity, &format!("{ratio:.2}%"))
                .label(" of ")
                .value(&sent.to_string())
                .label(" segments sent");
            let (retransmit_rate, retransmit_text) = rate("Tcp.RetransSegs", " retransmits/s");
            let (timeout_rate, timeout_text) = rate("TcpExt.TCPTimeouts", " timeouts/s");
            tooltip
                .line()
                .label(&format!("Last {seconds:.0}s: "))
                .high(retransmit_rate, &retransmit_text, 10.0, 100.0)
                .label(", ")
                .high(timeout_rate, &timeout_text, 1.0, 10.0)
                .label(", ")
                .value(&format!("{:.0} segments out/s, {:.0} in/s", per_second("Tcp.OutSegs"), per_second("Tcp.InSegs")));
        }
        if items.connections {
            tooltip
                .line()
                .label("Established connections: ")
                .value(&counters.protocol.get("Tcp.CurrEstab").copied().unwrap_or(0).to_string())
                .label(" · new: ")
                .value(&format!("{:.0}/s outgoing, {:.0}/s incoming", per_second("Tcp.ActiveOpens"), per_second("Tcp.PassiveOpens")));
        }
        let fault_line = |tooltip: &mut Markup<'_>, title: &str, first: (&str, &str), joiner: &str, second: (&str, &str)| {
            let (first_rate, first_text) = rate(first.0, first.1);
            tooltip.line().label(title).high(first_rate, &first_text, 0.01, 10.0).label(joiner);
            if second.0.is_empty() {
                tooltip.value(second.1);
            } else {
                let (second_rate, second_text) = rate(second.0, second.1);
                tooltip.high(second_rate, &second_text, 0.01, 10.0);
            }
        };
        if items.listen_queue {
            fault_line(&mut tooltip, "Listen queue: ", ("TcpExt.ListenOverflows", " overflows/s"), ", ", ("TcpExt.ListenDrops", " drops/s"));
        }
        if items.udp_errors {
            fault_line(&mut tooltip, "UDP buffer errors: receive ", ("Udp.RcvbufErrors", "/s"), ", send ", ("Udp.SndbufErrors", "/s"));
        }
        if items.kernel_backlog {
            let squeezes = format!("{:.0} time squeezes/s", per_second("Softnet.TimeSqueeze"));
            fault_line(&mut tooltip, "Kernel backlog: ", ("Softnet.Dropped", " drops/s"), ", ", ("", &squeezes));
        }

        let default_route = default_route(self.route.read());
        if items.interfaces {
            tooltip.heading("Interfaces");
            match &default_route {
                Some((interface, gateway)) => {
                    tooltip.line().label("Default route: ").value(interface).label(" via ").value(gateway);
                }
                None => {
                    tooltip.line().toned(Severity::Warning, "No default route");
                }
            }
            let addresses = interface_addresses();
            let mut names: Vec<&String> = counters.interfaces.keys().collect();
            names.sort();
            for name in names {
                let state = read_trimmed(format!("/sys/class/net/{name}/operstate")).unwrap_or_default();
                if name == "lo" || state == "down" {
                    continue;
                }
                let speed: f64 = read_trimmed(format!("/sys/class/net/{name}/speed")).and_then(|speed| speed.parse().ok()).unwrap_or(0.0);
                let speed_text = if speed > 0.0 { format!(", {speed:.0} Mb/s") } else { String::new() };
                let routable = addresses.get(name).map_or_else(|| "no routable addresses".to_owned(), |list| list.join(" "));
                tooltip.line().value(name).label(&format!(" ({}{speed_text}): ", state.to_uppercase())).value(&routable);
                if std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists() {
                    tooltip.line().label("  ").value(&wifi_link(name));
                }
                let (Some(current), Some(earlier)) = (counters.interfaces.get(name), previous.interfaces.get(name)) else { continue };
                let change = |field: fn(&InterfaceCounters) -> u64| field(current).saturating_sub(field(earlier)) as f64 / seconds;
                let link_bytes_per_second = speed * 125_000.0;
                for (direction, bytes, packets, drops, errors) in [
                    ("receive", change(|c| c.receive_bytes), change(|c| c.receive_packets), change(|c| c.receive_drops), change(|c| c.receive_errors)),
                    ("send", change(|c| c.send_bytes), change(|c| c.send_packets), change(|c| c.send_drops), change(|c| c.send_errors)),
                ] {
                    tooltip.line().label(&format!("  {direction} ")).value(&format!("{:.2} MiB/s", bytes / 1_048_576.0));
                    if link_bytes_per_second > 0.0 {
                        let percent = 100.0 * bytes / link_bytes_per_second;
                        tooltip.label(" (").high(percent, &format!("{percent:.0}%"), 70.0, 90.0).label(" of link)");
                    }
                    tooltip
                        .label(", ")
                        .value(&format!("{packets:.0} packets/s"))
                        .label(", ")
                        .high(drops, &format!("{drops:.0} drops/s"), 0.01, 10.0)
                        .label(", ")
                        .high(errors, &format!("{errors:.0} errors/s"), 0.01, 10.0);
                }
            }

        }

        let alt = match &default_route {
            None => "disconnected",
            Some((interface, _)) if std::path::Path::new(&format!("/sys/class/net/{interface}/wireless")).exists() => "wifi",
            Some(_) => "ethernet",
        };
        let mut headline = Markup::new(colors);
        if default_route.is_none() {
            headline.label("offline");
            return WaybarReport { class: "disconnected", alt, ..WaybarReport::new(headline.into_text(), tooltip.into_text(), Severity::Ok) };
        }
        headline.high(nas_wait, &format!("{nas_wait:.2}"), 4.0, 16.0);
        // Strain in the tooltip's fault counters, link use and errors raises the class, as does the
        // retransmission ratio; the separate retransmit and timeout rates are informational.
        let severity = headline.worst_severity().max(ratio_severity).max(tooltip.worst_severity().min(Severity::Warning));
        WaybarReport { alt, ..WaybarReport::new(headline.into_text(), tooltip.into_text(), severity) }
    }
}

/// /proc/net/snmp and /proc/net/netstat pair a header row with a value row per protocol.
fn parse_header_value_pairs(text: &str, into: &mut HashMap<String, u64>) {
    let mut lines = text.lines();
    while let (Some(header), Some(values)) = (lines.next(), lines.next()) {
        let mut names = header.split_whitespace();
        let mut numbers = values.split_whitespace();
        let Some(protocol) = names.next().map(|name| name.trim_end_matches(':')) else { continue };
        numbers.next();
        for (name, number) in names.zip(numbers) {
            into.insert(format!("{protocol}.{name}"), number.parse().unwrap_or(0));
        }
    }
}

/// The lowest-metric default route as (interface, gateway).
fn default_route(table: &str) -> Option<(String, String)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.len() > 6 && fields[1] == "00000000").then(|| {
                let gateway = u32::from_str_radix(fields[2], 16).unwrap_or(0).to_le_bytes();
                (fields[6].parse::<u64>().unwrap_or(u64::MAX), fields[0].to_owned(), std::net::Ipv4Addr::from(gateway).to_string())
            })
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, interface, gateway)| (interface, gateway))
}

/// Routable addresses with prefix lengths by interface; link-local IPv6 addresses are left out.
fn interface_addresses() -> BTreeMap<String, Vec<String>> {
    let mut addresses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for interface in nix::ifaddrs::getifaddrs().into_iter().flatten() {
        let (Some(address), netmask) = (interface.address, interface.netmask) else { continue };
        let prefix = |bits: Option<u32>| bits.map_or_else(String::new, |bits| format!("/{bits}"));
        let text = if let Some(ipv4) = address.as_sockaddr_in() {
            format!("{}{}", ipv4.ip(), prefix(netmask.and_then(|mask| mask.as_sockaddr_in().map(|mask| mask.ip().to_bits().count_ones()))))
        } else if let Some(ipv6) = address.as_sockaddr_in6() {
            if ipv6.ip().is_unicast_link_local() {
                continue;
            }
            format!("{}{}", ipv6.ip(), prefix(netmask.and_then(|mask| mask.as_sockaddr_in6().map(|mask| mask.ip().to_bits().count_ones()))))
        } else {
            continue;
        };
        addresses.entry(interface.interface_name).or_default().push(text);
    }
    addresses
}

/// SSID, signal and bitrate from `iw`, run only for wireless interfaces.
fn wifi_link(interface: &str) -> String {
    let Ok(output) = std::process::Command::new("iw").args(["dev", interface, "link"]).output() else {
        return "Wi-Fi details unavailable (iw not found)".to_owned();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let after = |prefix: &str| text.lines().find_map(|line| line.trim().strip_prefix(prefix).map(str::trim).map(str::to_owned));
    after("SSID:").map_or_else(
        || "Wi-Fi not associated".to_owned(),
        |ssid| {
            format!(
                "Wi-Fi {ssid}, signal {}, bitrate {}",
                after("signal:").unwrap_or_default(),
                after("tx bitrate:").map(|rate| rate.split_whitespace().take(2).collect::<Vec<_>>().join(" ")).unwrap_or_default()
            )
        },
    )
}
