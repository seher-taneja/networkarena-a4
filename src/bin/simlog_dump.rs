use competitive_net_sim::sim_log::{self, LogEvent};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let path = args.get(1).cloned().unwrap_or_else(|| "/tmp/routing.simlog".into());
    let switch_filter: Option<u32> = args.get(2).and_then(|s| s.parse().ok());
    let bytes = std::fs::read(&path).expect("read log");
    let frames = sim_log::writer::decode_all(&bytes).expect("decode");
    println!("# {} frames in {}", frames.len(), path);
    for f in &frames {
        match &f.event {
            LogEvent::TableEntryInstalled { switch, table, entry } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!(
                        "{:>10} ns  S{}  install  t{}  entry id={} key=0x{:x}/{} -> {:?}",
                        f.at_ns, switch, table, entry.id.0, entry.key, entry.prefix_len, entry.action
                    );
                }
            }
            LogEvent::TableEntryDeleted { switch, table, entry_id } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!(
                        "{:>10} ns  S{}  delete   t{}  entry id={}",
                        f.at_ns, switch, table, entry_id
                    );
                }
            }
            LogEvent::SwitchAdded { id, num_ports, .. } => {
                if switch_filter.map_or(true, |s| s == *id) {
                    println!("{:>10} ns  S{}  switch, {} ports", f.at_ns, id, num_ports);
                }
            }
            LogEvent::PortQueuesConfigured { switch, port, discipline, queues, .. } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    let caps: Vec<u32> = queues.iter().map(|q| q.max_packets).collect();
                    println!(
                        "{:>10} ns  S{}  queues  port {}  discipline {}  packets {:?}",
                        f.at_ns, switch, port, discipline, caps
                    );
                }
            }
            LogEvent::LinkFailed { id } => {
                println!("{:>10} ns  link L{} FAILED", f.at_ns, id);
            }
            LogEvent::LinkRestored { id } => {
                println!("{:>10} ns  link L{} restored", f.at_ns, id);
            }
            LogEvent::ProgramInstalled { switch, .. } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!("{:>10} ns  S{}  PROGRAM INSTALLED", f.at_ns, switch);
                }
            }
            LogEvent::LinkDeclared { switch, port, up } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    let says = if *up { "up" } else { "DOWN" };
                    println!("{:>10} ns  S{}  declares port {} {}", f.at_ns, switch, port, says);
                }
            }
            LogEvent::ObservationDropped { switch, cap, packet_id } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    let what = match *cap {
                        sim_log::CAP_EXPORT => "report over export budget",
                        sim_log::CAP_REPORT_SIZE => "report over the size cap",
                        _ => "event over budget",
                    };
                    println!("{:>10} ns  S{}  LOST {}  pkt {:#x}", f.at_ns, switch, what, packet_id);
                }
            }
            LogEvent::PacketSampled { switch, reason, packet_id } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!("{:>10} ns  S{}  sample  reason {}  pkt {:#x}", f.at_ns, switch, reason, packet_id);
                }
            }
            LogEvent::LoggingSwitchNamed { switch, accepted } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    let says = if *accepted { "is the logging switch" } else { "asked to log: REFUSED" };
                    println!("{:>10} ns  S{}  {}", f.at_ns, switch, says);
                }
            }
            LogEvent::TeamLogWritten { switch, bytes } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!("{:>10} ns  S{}  log write  {} B", f.at_ns, switch, bytes.len());
                }
            }
            LogEvent::TeamLogRefused { switch, len, why } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    let what = if *why == competitive_net_sim::team_log::REFUSED_FULL { "log full" } else { "not the logging switch" };
                    println!("{:>10} ns  S{}  log write  {} B  LOST ({})", f.at_ns, switch, len, what);
                }
            }
            LogEvent::DroppedAtPort { switch, port, packet_id } => {
                if switch_filter.map_or(true, |s| s == *switch) {
                    println!("{:>10} ns  S{}  refused at port {}  pkt {:#x}", f.at_ns, switch, port, packet_id);
                }
            }
            LogEvent::CustomerNamed { app, prefix, len, name } => {
                let p = prefix.to_be_bytes();
                println!("{:>10} ns  customer  {}.{}.{}.{}/{}  is {}  (app {})", f.at_ns, p[0], p[1], p[2], p[3], len, name, app);
            }
            LogEvent::PacketIngress { packet, .. } => {
                if packet.ip_proto == 254 {
                    let dst = packet.ip_dst;
                    let stale_dst = (dst >> 16) & 0xff;
                    let from_sw = (dst >> 8) & 0xff;
                    let fh = dst & 0xff;
                    let port = packet.ip_src & 0xffff;
                    if switch_filter.map_or(true, |s| s == from_sw) {
                        let fh_str = if fh == 0xff { "none".into() } else { format!("S{}", fh) };
                        let port_str = if port == 0xffff { "none".into() } else { port.to_string() };
                        println!(
                            "{:>10} ns  S{}  DIAG  delete-S{}; first_hop={} port={}",
                            f.at_ns, from_sw, stale_dst, fh_str, port_str,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}
