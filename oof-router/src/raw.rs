use std::ops::Deref;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::io;
use std::fs;
use std::net::{Ipv4Addr, ToSocketAddrs};

use log::{debug, warn, error};
use ipnetwork::{IpNetwork, Ipv4Network};
use nix::poll::{EventFlags, PollFd, poll};
use pnet::datalink::{self, MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::{PacketSize, Packet, MutablePacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::icmp::{self, IcmpTypes, IcmpPacket};
use pnet::packet::icmp::destination_unreachable::{self, DestinationUnreachablePacket, MutableDestinationUnreachablePacket};
use pnet::packet::tcp::{self, MutableTcpPacket};
use pnet::packet::udp::{self, MutableUdpPacket};

use oof_common::net::{LinkSpeed, Link};
use crate::{Error, Result, client};

const BROADCAST_MAC: MacAddr = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

pub fn iface_speed(iface: &str) -> Option<LinkSpeed> {
    match fs::read(format!("/sys/class/net/{}/speed", iface)) {
        Err(_) => None,
        Ok(c) => match String::from_utf8(c) {
            Err(_) => None,
            Ok(s) => match s.trim().parse() {
                Err(_) => None,
                Ok(s) => LinkSpeed::from_value(s),
            }
        }
    }
}
pub fn iface_mtu(iface: &str) -> Option<u32> {
    match fs::read(format!("/sys/class/net/{}/mtu", iface)) {
        Err(_) => None,
        Ok(c) => match String::from_utf8(c) {
            Err(_) => None,
            Ok(s) => match s.trim().parse() {
                Err(_) => None,
                Ok(mtu) => Some(mtu),
            }
        }
    }
}

struct RawInterface {
    iface: NetworkInterface,
    link: Link,
    tx: Box<DataLinkSender>,
    rx: Box<DataLinkReceiver>,
}
impl Deref for RawInterface {
    type Target = NetworkInterface;
    fn deref(&self) -> &Self::Target {
        &self.iface
    }
}
impl RawInterface {
    pub fn new(link: Link, iface: NetworkInterface) -> Result<RawInterface> {
        let mtu = iface_mtu(&iface.name).ok_or(Error::Mtu(iface.name.clone()))?;

        let mut if_conf = datalink::Config::default();
        if_conf.read_buffer_size = EthernetPacket::minimum_packet_size() + mtu as usize;
        if_conf.read_timeout = Some(Duration::from_millis(0));
        let (tx, rx) = match datalink::channel(&iface, if_conf)? {
            datalink::Channel::Ethernet(tx, rx) => (tx, rx),
            _ => unreachable!(),
        };

        Ok(RawInterface {
            iface,
            link,
            tx,
            rx,
        })
    }
}

struct RawRouterInner {
    routes: client::Router,
    interfaces: HashMap<Ipv4Network, RawInterface>,
    read_poll_fds: Vec<PollFd>,
    packet_queue: VecDeque<(Ipv4Network, MutableEthernetPacket<'static>)>,
    arp_table: HashMap<Ipv4Addr, MacAddr>,
}
impl RawRouterInner {
    pub fn new(routes: client::Router) -> Result<RawRouterInner> {
        let ctl_ip = routes.addr().ip();
        let mut links = Vec::new();
        let mut interfaces = HashMap::new();
        let mut arp_table = HashMap::new();
        'outer: for iface in datalink::interfaces() {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }

            let mut addr = None;
            for net in &iface.ips {
                if net.contains(ctl_ip) {
                    continue 'outer;
                }
                match net {
                    IpNetwork::V6(_) => continue,
                    IpNetwork::V4(n) => addr = Some(*n),
                }
            }

            if let Some(a) = addr {
                let link = Link::new(a, iface_speed(&iface.name).unwrap_or(LinkSpeed::Gigabit));
                links.push(link);
                arp_table.insert(a.ip(), iface.mac.expect("iface has no mac address??"));
                interfaces.insert(a, (link, iface));
            }
        }
        routes.update_links(links)?;

        let mut read_poll_fds = Vec::new();
        let interfaces = {
            match interfaces.into_iter()
                .map(|(a, (link, iface))| {
                    let iface = RawInterface::new(link, iface)?;
                    read_poll_fds.push(PollFd::new(iface.rx.raw_fd(), EventFlags::POLLIN));
                    Ok((a, iface))
                })
                .collect() {
                Ok(i) => i,
                Err(e) => return Err(e),
            }
        };

        Ok(RawRouterInner {
            routes,
            interfaces,
            read_poll_fds,
            packet_queue: VecDeque::new(),
            arp_table,
        })
    }

    fn arp_lookup(&mut self, src_link: Ipv4Network, target: Ipv4Addr) -> Result<MacAddr> {
        if let Some(a) = self.arp_table.get(&target) {
            return Ok(*a);
        }

        let src_mac = self.arp_table[&src_link.ip()];
        let iface = self.interfaces.get_mut(&src_link).unwrap();

        let mut arp = MutableArpPacket::owned(vec![0; ArpPacket::minimum_packet_size()]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_link.ip());
        arp.set_target_proto_addr(target);

        let mut ethernet = MutableEthernetPacket::owned(vec![0; EthernetPacket::minimum_packet_size() + arp.packet_size()]).unwrap();
        ethernet.set_destination(BROADCAST_MAC);
        ethernet.set_source(src_mac);
        ethernet.set_ethertype(EtherTypes::Arp);
        ethernet.set_payload(&arp.packet()[..arp.packet_size()]);

        debug!("arp size: {}, encapsulated eth size: {}", arp.packet_size(), ethernet.packet_size());
        iface.tx.send_to(&ethernet.packet()[..ethernet.packet_size() + arp.packet_size()], None).unwrap()?;

        let start = Instant::now();
        let target_mac = loop {
            if start.elapsed() >= Duration::from_millis(500) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out").into());
            }
            match poll(&mut [ PollFd::new(iface.rx.raw_fd(), EventFlags::POLLIN) ], 100) {
                Ok(0) => continue,
                _ => {},
            }

            let packet = EthernetPacket::new(iface.rx.next()?).unwrap();
            if packet.get_ethertype() == EtherTypes::Arp {
                let packet = ArpPacket::new(packet.payload()).expect("invalid arp packet");
                if packet.get_operation() == ArpOperations::Reply &&
                    packet.get_protocol_type() == EtherTypes::Ipv4 &&
                    packet.get_target_hw_addr() == src_mac &&
                    packet.get_target_proto_addr() == src_link.ip() &&
                    packet.get_sender_proto_addr() == target {
                    break packet.get_sender_hw_addr()
                }
            }

            self.packet_queue.push_back((iface.link.network, MutableEthernetPacket::owned(packet.packet().to_owned()).unwrap()));
        };

        debug!("arp reply: {} -> {}", target, target_mac);
        self.arp_table.insert(target, target_mac);
        Ok(target_mac)
    }
    fn send_net_unreachable(&mut self, src_link: Ipv4Network, orig: Ipv4Packet) -> Result<()> {
        assert!(src_link.contains(orig.get_source()));

        let orig_ip_slice = &orig.packet()[..(orig.get_header_length() as usize * 4) + 8];
        let mut unreachable = MutableDestinationUnreachablePacket::owned(vec![0;
                                                                         DestinationUnreachablePacket::minimum_packet_size() +
                                                                         orig_ip_slice.len()]).unwrap();
        unreachable.set_icmp_type(IcmpTypes::DestinationUnreachable);
        unreachable.set_icmp_code(destination_unreachable::IcmpCodes::DestinationNetworkUnknown);
        unreachable.set_payload(&orig.packet()[..orig_ip_slice.len()]);
        unreachable.set_checksum(icmp::checksum(&IcmpPacket::new(unreachable.packet()).unwrap()));

        let mut ip = MutableIpv4Packet::owned(vec![0;
                                              Ipv4Packet::minimum_packet_size() +
                                              unreachable.packet().len()]).unwrap();
        ip.set_version(4);
        ip.set_header_length(20 / 4);
        ip.set_dscp(0);
        ip.set_ecn(0);
        ip.set_total_length(ip.packet().len() as u16);
        ip.set_identification(0);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src_link.ip());
        ip.set_destination(orig.get_source());
        ip.set_payload(unreachable.packet());
        ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

        let dst_mac = self.arp_lookup(src_link, orig.get_source())?;
        let src_mac = self.arp_table[&src_link.ip()];
        let mut ethernet = MutableEthernetPacket::owned(vec![0;
                                                        EthernetPacket::minimum_packet_size() +
                                                        ip.packet().len()]).unwrap();
        ethernet.set_destination(dst_mac);
        ethernet.set_source(src_mac);
        ethernet.set_ethertype(EtherTypes::Ipv4);
        ethernet.set_payload(ip.packet());

        let iface = self.interfaces.get_mut(&src_link).unwrap();
        iface.tx.send_to(ethernet.packet(), None).unwrap()?;
        Ok(())
    }
    fn handle_packet(&mut self, in_net: Ipv4Network, mut ethernet: MutableEthernetPacket) -> Result<()> {
        match ethernet.get_ethertype() {
            EtherTypes::Arp => {
                let mut arp = match MutableArpPacket::new(ethernet.payload_mut()) {
                    Some(p) => p,
                    None => {
                            warn!("received invalid arp packet on {} [mac: {}, dst mac: {}] from {}",
                                  in_net, self.arp_table[&in_net.ip()], ethernet.get_destination(), ethernet.get_source());
                            return Ok(());
                    },
                };

                if arp.get_operation() != ArpOperations::Request ||
                        arp.get_protocol_type() != EtherTypes::Ipv4 ||
                        !in_net.contains(arp.get_sender_proto_addr()) ||
                        arp.get_target_proto_addr() != in_net.ip() {
                    debug!("ignoring arp request on {}", in_net);
                    return Ok(());
                }

                let src_mac = arp.get_sender_hw_addr();
                arp.set_operation(ArpOperations::Reply);
                arp.set_sender_hw_addr(self.arp_table[&in_net.ip()]);
                arp.set_target_hw_addr(src_mac);
                arp.set_target_proto_addr(arp.get_sender_proto_addr());
                arp.set_sender_proto_addr(in_net.ip());

                ethernet.set_destination(ethernet.get_source());
                ethernet.set_source(self.arp_table[&in_net.ip()]);

                debug!("sending arp reply to {} (for {})", src_mac, in_net.ip());
                self.interfaces.get_mut(&in_net).unwrap().tx.send_to(ethernet.packet(), None).unwrap()?;
            },
            EtherTypes::Ipv4 => {
                let mut ip = match MutableIpv4Packet::new(ethernet.payload_mut()) {
                    Some(p) => p,
                    None => {
                        warn!("received invalid ip packet on {} [mac: {}, dst mac: {}] from {}",
                              in_net, self.arp_table[&in_net.ip()], ethernet.get_destination(), ethernet.get_source());
                        return Ok(());
                    },
                };
                let src_ip = ip.get_source();
                let dst_ip = ip.get_destination();

                if ip.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).expect("bad tcp packet");
                    tcp.set_checksum(tcp::ipv4_checksum(&tcp.to_immutable(), &src_ip, &dst_ip));
                }
                if ip.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                    let mut udp = MutableUdpPacket::new(ip.payload_mut()).expect("bad tcp packet");
                    udp.set_checksum(udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip));
                }

                ip.set_ttl(ip.get_ttl() - 1);
                ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

                if in_net.contains(dst_ip) {
                    debug!("ignoring packet that should be handled by kernel");
                    return Ok(());
                }

                let (out_net, mut hop) = match self.routes.find_route(dst_ip) {
                    Ok(r) => r,
                    Err(Error::NoRoute(_)) => {
                        warn!("controller has no route to {}, sending icmp network unreachable to {}", dst_ip, src_ip);
                        self.send_net_unreachable(in_net, ip.to_immutable())?;
                        return Ok(());
                    },
                    Err(e) => return Err(e),
                };
                if out_net.contains(dst_ip) {
                    hop = dst_ip;
                }

                let dst_mac = self.arp_lookup(out_net, hop)?;
                let src_mac = self.arp_table[&out_net.ip()];
                ethernet.set_destination(dst_mac);
                ethernet.set_source(src_mac);
                
                debug!("forwarding {} byte ethernet packet from {} to {} via {}", ethernet.payload().len(), src_ip, dst_ip, out_net);
                self.interfaces.get_mut(&out_net).unwrap().tx.send_to(ethernet.packet(), None).unwrap()?;
            },
            t => debug!("ignoring ethernet packet of type {}", t),
        }
        Ok(())
    }
    pub fn read_and_process(&mut self) -> Result<()> {
        match poll(&mut self.read_poll_fds, 500) {
            Ok(0) => return Ok(()),
            _ => {},
        }

        while !self.packet_queue.is_empty() {
            let (iface_net, packet) = self.packet_queue.pop_front().unwrap();
            self.handle_packet(iface_net, packet)?;
        }
        for iface_net in self.interfaces.keys().map(|k| *k).collect::<Vec<_>>() {
            let packet = match self.interfaces.get_mut(&iface_net).unwrap().rx.next() {
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(e.into()),
                Ok(data) => {
                    MutableEthernetPacket::owned(data.to_owned()).expect("received invalid ethernet packet")
                },
            };

            self.handle_packet(iface_net, packet)?;
        }

        Ok(())
    }
    pub fn stop(self) {
        self.routes.stop();
    }
}

pub struct RawRouter {
    running: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}
impl RawRouter {
    pub fn start<A: ToSocketAddrs, E: Fn(Error) + Send + 'static>(addr: A, err_handler: E) -> Result<RawRouter> {
        let routes = client::Router::connect(addr, err_handler)?;

        let (tx, rx) = mpsc::sync_channel::<Result<()>>(0);
        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let running = Arc::clone(&running);
            thread::spawn(move || {
                let mut inner = match (|| {
                    Ok(RawRouterInner::new(routes)?)
                })() {
                    Ok(inner) => {
                        tx.send(Ok(())).unwrap();
                        inner
                    },
                    Err(e) => {
                        tx.send(Err(e)).unwrap();
                        return;
                    },
                };

                while running.load(Ordering::SeqCst) {
                    match inner.read_and_process() {
                        Ok(()) => {},
                        Err(e) => error!("error processing incoming packets: {}", e),
                    }
                }
                inner.stop();
            })
        };

        rx.recv().unwrap()?;
        Ok(RawRouter {
            running,
            thread,
        })
    }

    pub fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        self.thread.join().expect("thread panicked");
    }
}
