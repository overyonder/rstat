//! Network section: time spent waiting on the NAS over SMB, TCP and UDP health, and interfaces.
//! Headline: current number of SMB requests on the wire.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::alerts::Figure;
use crate::config::NetworkConfig;
use crate::markup::{Markup, MarkupColors, Severity, WaybarReport};
use crate::procfs_file::{ProcfsFile, read_trimmed};

/// How far back the retransmission ratio looks, so idle intervals don't dominate it.
const RETRANSMISSION_WINDOW: Duration = Duration::from_mins(1);

/// Below this many segments sent in the window a retransmission ratio is too noisy to read as strain.
const RETRANSMISSION_MINIMUM_SEGMENTS: u64 = 500;

/// The SMB client's completed commands and their elapsed time. Each Stats table declares its HZ.
#[derive(Clone, Copy, Default)]
struct SmbTotals {
    requests: u64,
    seconds: f64,
}

/// /proc/net/dev counters for one interface.
#[derive(Clone, Copy, Default)]
struct InterfaceCounters {
    receive_bytes: u64,
    receive_packets: u64,
    receive_errors: u64,
    receive_drops: u64,
    send_bytes: u64,
    send_packets: u64,
    send_errors: u64,
    send_drops: u64,
}

/// Cumulative counters at one sample.
#[derive(Clone, Default)]
struct NetworkCounters {
    protocol: HashMap<String, u64>, // "Tcp.OutSegs", "TcpExt.ListenOverflows", "Softnet.Dropped", ...
    interfaces: HashMap<String, InterfaceCounters>,
    smb: Option<SmbTotals>,
}

pub(crate) struct NetworkSampler {
    dev: ProcfsFile,
    snmp: ProcfsFile,
    netstat: ProcfsFile,
    softnet: ProcfsFile,
    route: ProcfsFile,
    route_ipv6: Option<ProcfsFile>,
    cifs_stats: Option<ProcfsFile>,
    cifs_debug: Option<ProcfsFile>,
    previous: Option<(Instant, NetworkCounters)>,
    retransmits: VecDeque<(Instant, Instant, u64, u64)>, // Start, end, segments sent, retransmitted
    items: NetworkConfig,
}

impl NetworkSampler {
    pub(crate) fn open(items: NetworkConfig) -> std::io::Result<Self> {
        let open = |path: &str| {
            ProcfsFile::open(path)
                .ok_or_else(|| std::io::Error::other(format!("cannot open {path}")))
        };
        Ok(Self {
            dev: open("/proc/net/dev")?,
            snmp: open("/proc/net/snmp")?,
            netstat: open("/proc/net/netstat")?,
            softnet: open("/proc/net/softnet_stat")?,
            route: open("/proc/net/route")?,
            route_ipv6: ProcfsFile::open("/proc/net/ipv6_route"),
            cifs_stats: ProcfsFile::open("/proc/fs/cifs/Stats"),
            cifs_debug: ProcfsFile::open("/proc/fs/cifs/DebugData"),
            previous: None,
            retransmits: VecDeque::new(),
            items,
        })
    }

    fn read_counters(&mut self) -> Option<NetworkCounters> {
        let mut protocol = HashMap::new();
        for file in [&mut self.snmp, &mut self.netstat] {
            parse_header_value_pairs(file.read(), &mut protocol);
        }
        if [
            "Tcp.OutSegs",
            "Tcp.InSegs",
            "Tcp.RetransSegs",
            "Tcp.CurrEstab",
            "Tcp.ActiveOpens",
            "Tcp.PassiveOpens",
            "TcpExt.TCPTimeouts",
            "TcpExt.ListenOverflows",
            "TcpExt.ListenDrops",
            "Udp.RcvbufErrors",
            "Udp.SndbufErrors",
        ]
        .iter()
        .any(|name| !protocol.contains_key(*name))
        {
            return None;
        }
        let (mut dropped, mut squeezed) = (0, 0);
        let softnet = self.softnet.read();
        if softnet.is_empty() {
            return None;
        }
        for line in softnet.lines() {
            let fields: Vec<u64> = line
                .split_whitespace()
                .take(3)
                .map(|field| u64::from_str_radix(field, 16))
                .collect::<Result<_, _>>()
                .ok()?;
            dropped += fields.get(1)?;
            squeezed += fields.get(2)?;
        }
        protocol.insert("Softnet.Dropped".to_owned(), dropped);
        protocol.insert("Softnet.TimeSqueeze".to_owned(), squeezed);

        let dev = self.dev.read();
        if dev.is_empty() {
            return None;
        }
        let interfaces = dev
            .lines()
            .skip(2)
            .map(|line| {
                let (name, counters) = line.split_once(':')?;
                let fields: Vec<u64> = counters
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<Result<_, _>>()
                    .ok()?;
                let field = |index: usize| fields.get(index).copied();
                Some((
                    name.trim().to_owned(),
                    InterfaceCounters {
                        receive_bytes: field(0)?,
                        receive_packets: field(1)?,
                        receive_errors: field(2)?,
                        receive_drops: field(3)?,
                        send_bytes: field(8)?,
                        send_packets: field(9)?,
                        send_errors: field(10)?,
                        send_drops: field(11)?,
                    },
                ))
            })
            .collect::<Option<_>>()?;

        let mut smb = None;
        if let Some(stats) = &mut self.cifs_stats {
            let mut ticks_per_second = None;
            for line in stats.read().lines() {
                if line.starts_with("Total time spent processing by command") {
                    ticks_per_second = line
                        .split_once("jiffies (")
                        .and_then(|(_, text)| text.split_whitespace().next()?.parse::<f64>().ok())
                        .filter(|hz| *hz > 0.0);
                    if ticks_per_second.is_some() {
                        smb.get_or_insert_with(SmbTotals::default);
                    }
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect();
                if let (Some(hz), Some(totals)) = (ticks_per_second, &mut smb)
                    && fields.len() == 5
                    && fields[0].bytes().all(|byte| byte.is_ascii_digit())
                    && let (Ok(requests), Ok(ticks)) =
                        (fields[1].parse::<u64>(), fields[2].parse::<u64>())
                {
                    totals.requests += requests;
                    totals.seconds += ticks as f64 / hz;
                } else if line.trim().is_empty() {
                    ticks_per_second = None;
                }
            }
        }
        Some(NetworkCounters {
            protocol,
            interfaces,
            smb,
        })
    }

    pub(crate) fn sample(&mut self, colors: &MarkupColors) -> WaybarReport {
        let now = Instant::now();
        let Some(counters) = self.read_counters() else {
            self.previous = None;
            self.retransmits.clear();
            return WaybarReport::unavailable("Network counters unavailable");
        };
        let Some((previous_time, previous)) = self.previous.replace((now, counters.clone())) else {
            return WaybarReport {
                alt: "ethernet",
                ..WaybarReport::collecting_first_sample()
            };
        };
        let seconds = now.duration_since(previous_time).as_secs_f64();
        if counters.protocol.iter().any(|(name, value)| {
            name != "Tcp.CurrEstab"
                && previous
                    .protocol
                    .get(name)
                    .is_some_and(|earlier| value < earlier)
        }) {
            self.retransmits.clear();
            return WaybarReport::collecting_first_sample();
        }
        let delta = |name: &str| {
            counters
                .protocol
                .get(name)
                .copied()
                .unwrap_or(0)
                .saturating_sub(previous.protocol.get(name).copied().unwrap_or(0))
        };
        let per_second = |name: &str| delta(name) as f64 / seconds;

        self.retransmits.push_back((
            previous_time,
            now,
            delta("Tcp.OutSegs"),
            delta("Tcp.RetransSegs"),
        ));
        while self
            .retransmits
            .front()
            .is_some_and(|(_, end, _, _)| now.duration_since(*end) > RETRANSMISSION_WINDOW)
        {
            self.retransmits.pop_front();
        }
        let window_start = self
            .retransmits
            .front()
            .map_or(previous_time, |(start, _, _, _)| *start);
        let window_seconds = now.duration_since(window_start).as_secs_f64();
        let (sent, retransmitted) = self
            .retransmits
            .iter()
            .fold((0, 0), |(sent, retransmitted), (_, _, s, r)| {
                (sent + s, retransmitted + r)
            });
        let ratio = if sent > 0 {
            100.0 * retransmitted as f64 / sent as f64
        } else {
            0.0
        };
        let items = self.items;
        let ratio_severity = if items.retransmissions && sent >= RETRANSMISSION_MINIMUM_SEGMENTS {
            Severity::of_high(ratio, 2.0, 10.0)
        } else {
            Severity::Ok
        };

        let completed = counters
            .smb
            .zip(previous.smb)
            .filter(|(now, earlier)| {
                now.requests >= earlier.requests && now.seconds >= earlier.seconds
            })
            .map(|(now, earlier)| {
                (
                    now.requests - earlier.requests,
                    now.seconds - earlier.seconds,
                )
            });
        let debug = self
            .cifs_debug
            .as_mut()
            .map(|debug| debug.read().to_owned());
        let active_now = debug.as_ref().and_then(|debug| {
            debug.lines().find_map(|line| {
                line.strip_prefix("Active VFS Requests:")?
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
        });
        let nas_wait = debug.as_deref().and_then(smb_requests_on_wire);

        let mut tooltip = Markup::new(colors);
        if items.nas {
            tooltip.heading("NAS (SMB)");
            tooltip.line().label("Requests on wire now: ");
            if let Some(pending) = nas_wait {
                tooltip.high(pending as f64, &pending.to_string(), 4.0, 16.0);
            } else {
                tooltip.value("N/A");
            }
            tooltip
                .label(" · active VFS operations: ")
                .value(&active_now.map_or_else(|| "N/A".to_owned(), |count| count.to_string()));
            tooltip.line().label("Completed requests: ");
            if let Some((requests, elapsed)) = completed {
                tooltip
                    .value(&format!("{:.0}/s", requests as f64 / seconds))
                    .label(" · average time: ");
                if requests > 0 {
                    let latency = elapsed * 1000.0 / requests as f64;
                    tooltip.high(latency, &format!("{latency:.1} ms"), 20.0, 100.0);
                } else {
                    tooltip.value("N/A");
                }
            } else {
                tooltip.value("N/A");
            }
        }

        let rate =
            |name: &str, unit: &str| (per_second(name), format!("{:.0}{unit}", per_second(name)));
        if items.retransmissions
            || items.connections
            || items.listen_queue
            || items.udp_errors
            || items.kernel_backlog
        {
            tooltip.heading("TCP and UDP");
        }
        if items.retransmissions {
            tooltip
                .line()
                .label(&format!("Retransmissions over {window_seconds:.0}s: "));
            if sent > 0 {
                tooltip.toned(ratio_severity, &format!("{ratio:.2}%"));
            } else {
                tooltip.value("N/A");
            }
            tooltip
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
                .value(&format!(
                    "{:.0} segments out/s, {:.0} in/s",
                    per_second("Tcp.OutSegs"),
                    per_second("Tcp.InSegs")
                ));
        }
        if items.connections {
            tooltip
                .line()
                .label("Established / close-wait connections: ")
                .value(
                    &counters
                        .protocol
                        .get("Tcp.CurrEstab")
                        .copied()
                        .unwrap_or(0)
                        .to_string(),
                )
                .label(" · opens: ")
                .value(&format!(
                    "{:.0}/s active, {:.0}/s passive",
                    per_second("Tcp.ActiveOpens"),
                    per_second("Tcp.PassiveOpens")
                ));
        }
        let fault_line = |tooltip: &mut Markup<'_>,
                          title: &str,
                          first: (&str, &str),
                          joiner: &str,
                          second: (&str, &str)| {
            let (first_rate, first_text) = rate(first.0, first.1);
            tooltip
                .line()
                .label(title)
                .high(first_rate, &first_text, 0.01, 10.0)
                .label(joiner);
            if second.0.is_empty() {
                tooltip.value(second.1);
            } else {
                let (second_rate, second_text) = rate(second.0, second.1);
                tooltip.high(second_rate, &second_text, 0.01, 10.0);
            }
        };
        if items.listen_queue {
            fault_line(
                &mut tooltip,
                "Listen queue: ",
                ("TcpExt.ListenOverflows", " overflows/s"),
                ", ",
                ("TcpExt.ListenDrops", " drops/s"),
            );
        }
        if items.udp_errors {
            fault_line(
                &mut tooltip,
                "UDP buffer errors: receive ",
                ("Udp.RcvbufErrors", "/s"),
                ", send ",
                ("Udp.SndbufErrors", "/s"),
            );
        }
        if items.kernel_backlog {
            let squeezes = format!("{:.0} time squeezes/s", per_second("Softnet.TimeSqueeze"));
            fault_line(
                &mut tooltip,
                "Kernel backlog: ",
                ("Softnet.Dropped", " drops/s"),
                ", ",
                ("", &squeezes),
            );
        }

        let routes = self.route.read();
        if routes.is_empty() {
            return WaybarReport::unavailable("Routing counters unavailable");
        }
        let default_route = default_route(routes).or_else(|| {
            self.route_ipv6
                .as_mut()
                .and_then(|route| default_ipv6_route(route.read()))
        });
        if items.interfaces {
            tooltip.heading("Interfaces");
            match &default_route {
                Some((interface, gateway)) => {
                    tooltip
                        .line()
                        .label("Default route: ")
                        .value(interface)
                        .label(" via ")
                        .value(gateway);
                }
                None => {
                    tooltip.line().toned(Severity::Warning, "No default route");
                }
            }
            let addresses = interface_addresses();
            let mut names: Vec<&String> = counters.interfaces.keys().collect();
            names.sort();
            for name in names {
                let state = read_trimmed(format!("/sys/class/net/{name}/operstate"))
                    .unwrap_or_else(|| "N/A".to_owned());
                if name == "lo" || state == "down" {
                    continue;
                }
                let speed: f64 = read_trimmed(format!("/sys/class/net/{name}/speed"))
                    .and_then(|speed| speed.parse().ok())
                    .unwrap_or(0.0);
                let speed_text = if speed > 0.0 {
                    format!(", {speed:.0} Mb/s")
                } else {
                    String::new()
                };
                let routable = addresses.as_ref().map_or_else(
                    || "N/A".to_owned(),
                    |addresses| {
                        addresses.get(name).map_or_else(
                            || "no global or private addresses".to_owned(),
                            |list| list.join(" "),
                        )
                    },
                );
                tooltip
                    .line()
                    .value(name)
                    .label(&format!(" ({}{speed_text}): ", state.to_uppercase()))
                    .value(&routable);
                if std::path::Path::new(&format!("/sys/class/net/{name}/wireless")).exists() {
                    tooltip.line().label("  ").value(&wifi_link(name));
                }
                let (Some(current), Some(earlier)) =
                    (counters.interfaces.get(name), previous.interfaces.get(name))
                else {
                    continue;
                };
                let change = |field: fn(&InterfaceCounters) -> u64| {
                    field(current).saturating_sub(field(earlier)) as f64 / seconds
                };
                let link_bytes_per_second = speed * 125_000.0;
                for (direction, bytes, packets, drops, errors) in [
                    (
                        "receive",
                        change(|c| c.receive_bytes),
                        change(|c| c.receive_packets),
                        change(|c| c.receive_drops),
                        change(|c| c.receive_errors),
                    ),
                    (
                        "send",
                        change(|c| c.send_bytes),
                        change(|c| c.send_packets),
                        change(|c| c.send_drops),
                        change(|c| c.send_errors),
                    ),
                ] {
                    tooltip
                        .line()
                        .label(&format!("  {direction} "))
                        .value(&format!("{:.2} MiB/s", bytes / 1_048_576.0));
                    if link_bytes_per_second > 0.0 {
                        let percent = 100.0 * bytes / link_bytes_per_second;
                        tooltip
                            .label(" (")
                            .high(percent, &format!("{percent:.0}%"), 70.0, 90.0)
                            .label(" of link)");
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
            Some((interface, _))
                if std::path::Path::new(&format!("/sys/class/net/{interface}/wireless"))
                    .exists() =>
            {
                "wifi"
            }
            Some(_) => "ethernet",
        };
        let mut headline = Markup::new(colors);
        if default_route.is_none() {
            headline.label("no default route");
            return WaybarReport {
                class: "disconnected",
                alt,
                ..WaybarReport::new(headline.into_text(), tooltip.into_text(), Severity::Ok)
            };
        }
        if let Some(pending) = nas_wait {
            headline.high(pending as f64, &pending.to_string(), 4.0, 16.0);
        } else {
            headline.value("N/A");
        }
        // Strain in the tooltip's fault counters, link use and errors raises the class, as does the
        // retransmission ratio; the separate retransmit and timeout rates are informational.
        let severity = headline
            .worst_severity()
            .max(ratio_severity)
            .max(tooltip.worst_severity().min(Severity::Warning));
        let figures = nas_wait
            .into_iter()
            .map(|pending| (Figure::NetworkNasWait, pending as f64))
            .collect();
        WaybarReport {
            alt,
            figures,
            ..WaybarReport::new(headline.into_text(), tooltip.into_text(), severity)
        }
    }
}

/// /proc/net/snmp and /proc/net/netstat pair a header row with a value row per protocol.
fn parse_header_value_pairs(text: &str, into: &mut HashMap<String, u64>) {
    let mut lines = text.lines();
    while let (Some(header), Some(values)) = (lines.next(), lines.next()) {
        let mut names = header.split_whitespace();
        let mut numbers = values.split_whitespace();
        let Some(protocol) = names.next().map(|name| name.trim_end_matches(':')) else {
            continue;
        };
        numbers.next();
        for (name, number) in names.zip(numbers) {
            if let Ok(number) = number.parse() {
                into.insert(format!("{protocol}.{name}"), number);
            }
        }
    }
}

/// `DebugData` can repeat a connection under multiple sessions; count each `ConnectionId` once.
fn smb_requests_on_wire(debug: &str) -> Option<u64> {
    if !debug.contains("Servers:") {
        return None;
    }
    let mut connections = BTreeMap::new();
    let mut connection = None;
    for line in debug.lines() {
        if let Some((_, id)) = line.split_once("ConnectionId:") {
            connection = id.split_whitespace().next().map(str::to_owned);
        }
        if let Some((_, value)) = line.split_once("Req On Wire:") {
            connections.insert(
                connection.clone()?,
                value.split_whitespace().next()?.parse::<u64>().ok()?,
            );
        }
    }
    Some(connections.values().sum())
}

/// The lowest-metric default route as (interface, gateway).
fn default_route(table: &str) -> Option<(String, String)> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() <= 7
                || fields[1] != "00000000"
                || fields[7] != "00000000"
                || !u32::from_str_radix(fields[3], 16)
                    .is_ok_and(|flags| flags & 1 != 0 && flags & 0x200 == 0)
            {
                return None;
            }
            let gateway = u32::from_str_radix(fields[2], 16).ok()?.to_le_bytes();
            Some((
                fields[6].parse::<u64>().ok()?,
                fields[0].to_owned(),
                std::net::Ipv4Addr::from(gateway).to_string(),
            ))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, interface, gateway)| (interface, gateway))
}

/// IPv6 default routes with no source restriction, taking the lowest metric.
fn default_ipv6_route(table: &str) -> Option<(String, String)> {
    table
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 10
                || fields[0] != "00000000000000000000000000000000"
                || fields[1] != "00"
                || fields[3] != "00"
            {
                return None;
            }
            let flags = u32::from_str_radix(fields[8], 16).ok()?;
            if flags & 1 == 0 || flags & 0x200 != 0 {
                return None;
            }
            Some((
                u32::from_str_radix(fields[5], 16).ok()?,
                fields[9].to_owned(),
                std::net::Ipv6Addr::from(u128::from_str_radix(fields[4], 16).ok()?).to_string(),
            ))
        })
        .min_by_key(|(metric, _, _)| *metric)
        .map(|(_, interface, gateway)| (interface, gateway))
}

/// Routable addresses with prefix lengths by interface; link-local IPv6 addresses are left out.
fn interface_addresses() -> Option<BTreeMap<String, Vec<String>>> {
    let mut addresses: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for interface in nix::ifaddrs::getifaddrs().ok()? {
        let (Some(address), netmask) = (interface.address, interface.netmask) else {
            continue;
        };
        let prefix = |bits: Option<u32>| bits.map_or_else(String::new, |bits| format!("/{bits}"));
        let text = if let Some(ipv4) = address.as_sockaddr_in() {
            format!(
                "{}{}",
                ipv4.ip(),
                prefix(netmask.and_then(|mask| {
                    mask.as_sockaddr_in()
                        .map(|mask| mask.ip().to_bits().count_ones())
                }))
            )
        } else if let Some(ipv6) = address.as_sockaddr_in6() {
            if ipv6.ip().is_unicast_link_local() {
                continue;
            }
            format!(
                "{}{}",
                ipv6.ip(),
                prefix(netmask.and_then(|mask| {
                    mask.as_sockaddr_in6()
                        .map(|mask| mask.ip().to_bits().count_ones())
                }))
            )
        } else {
            continue;
        };
        addresses
            .entry(interface.interface_name)
            .or_default()
            .push(text);
    }
    Some(addresses)
}

/// SSID, signal and bitrate from `iw`, run only for wireless interfaces.
fn wifi_link(interface: &str) -> String {
    let Ok(output) = std::process::Command::new("iw")
        .args(["dev", interface, "link"])
        .output()
    else {
        return "Wi-Fi details unavailable (iw not found)".to_owned();
    };
    if !output.status.success() {
        return "Wi-Fi link: N/A".to_owned();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let after = |prefix: &str| {
        text.lines().find_map(|line| {
            line.trim()
                .strip_prefix(prefix)
                .map(str::trim)
                .map(str::to_owned)
        })
    };
    after("SSID:").map_or_else(
        || "Wi-Fi not associated".to_owned(),
        |ssid| {
            format!(
                "Wi-Fi {ssid}, signal {}, bitrate {}",
                after("signal:").unwrap_or_else(|| "N/A".to_owned()),
                after("tx bitrate:").map_or_else(
                    || "N/A".to_owned(),
                    |rate| rate
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            )
        },
    )
}
