use std::ops::Deref;
use std::mem;
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
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{self, MutableTcpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};

use oof_common::net::{LinkSpeed, Link, Route};
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
    mtu: u32,
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
            mtu,
            tx,
            rx,
        })
    }
}

struct RawRouterInner {
    routes: client::Router,
    interfaces: HashMap<Ipv4Network, RawInterface>,
    read_poll_fds: Vec<PollFd>,
    packet_queue: Vec<(Ipv4Network, MutableEthernetPacket<'static>)>,
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
            packet_queue: Vec::new(),
            arp_table,
        })
    }

    fn arp_lookup(&mut self, route: Route) -> Result<MacAddr> {
        let (src, target) = route;
        if let Some(a) = self.arp_table.get(&target) {
            return Ok(*a);
        }

        let src_mac = self.arp_table[&src.ip()];
        let iface = self.interfaces.get_mut(&src).unwrap();

        let mut arp = MutableArpPacket::owned(vec![0; ArpPacket::minimum_packet_size()]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src.ip());
        arp.set_target_proto_addr(target);

        let mut ethernet = MutableEthernetPacket::owned(vec![0; 1518]).unwrap();
        ethernet.set_destination(BROADCAST_MAC);
        ethernet.set_source(src_mac);
        ethernet.set_ethertype(EtherTypes::Arp);
        ethernet.set_payload(&arp.packet()[..arp.packet_size()]);

        debug!("arp size: {}, encapsulated eth size: {}", arp.packet_size(), ethernet.packet_size());
        iface.tx.send_to(&ethernet.packet()[..ethernet.packet_size() + arp.packet_size()], None).unwrap()?;

        let start = Instant::now();
        let target_mac = loop {
            if start.elapsed() >= Duration::from_secs(2) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out").into());
            }
            match poll(&mut [ PollFd::new(iface.rx.raw_fd(), EventFlags::POLLIN) ], 100) {
                Ok(0) => continue,
                _ => {},
            }

            let packet = EthernetPacket::new(iface.rx.next()?).unwrap();
            if packet.get_ethertype() != EtherTypes::Arp {
                self.packet_queue.push((iface.link.network, MutableEthernetPacket::owned(packet.packet().to_owned()).unwrap()));
                continue;
            }

            let packet = ArpPacket::new(packet.payload()).expect("invalid arp packet");
            if packet.get_operation() != ArpOperations::Reply ||
                packet.get_protocol_type() != EtherTypes::Ipv4 ||
                packet.get_target_hw_addr() != src_mac ||
                packet.get_target_proto_addr() != src.ip() ||
                packet.get_sender_proto_addr() != target {
                self.packet_queue.push((iface.link.network, MutableEthernetPacket::owned(packet.packet().to_owned()).unwrap()));
                continue;
            }

            break packet.get_sender_hw_addr()
        };

        debug!("arp reply: {} -> {}", target, target_mac);
        self.arp_table.insert(target, target_mac);
        Ok(target_mac)
    }
    fn find_ether_peers(&mut self, ip_packet: Ipv4Packet) -> Result<(MacAddr, Ipv4Addr, MacAddr, &mut RawInterface)> {
        let dst_ip = ip_packet.get_destination();
        /*match self.arp_table.get(&dst_ip) {
            Some(a) => Ok((*a, dst_ip, self.arp_table[&ip_packet.get_source()], self.interfaces.get_mut(&in_net).unwrap())),
            None => {*/
                // b: 10.0.0.2/16, 10.0.0.2 -> 10.0.0.2/16, 10.0.0.1
                // a: 10.0.0.1/16, 10.0.0.1 -> 10.0.0.1/16, 10.0.0.1
                let (net, mut hop) = self.routes.find_route(dst_ip)?;
                if hop == dst_ip {
                    return Err(Error::DestinationReached(net));
                }

                if net.ip() == hop {
                    hop = dst_ip;
                }

                let dst_mac = self.arp_lookup((net, hop))?;
                let mut src_mac = self.arp_table[&net.ip()];
                
                let src_iface = if dst_mac == src_mac {
                    let loopback_net = "127.0.0.1/8".parse::<Ipv4Network>().unwrap();
                    src_mac = self.arp_table[&loopback_net.ip()];
                    self.interfaces.get_mut(&loopback_net).unwrap()
                } else {
                    self.interfaces.get_mut(&net).unwrap()
                };
                Ok((dst_mac, hop, src_mac, src_iface))
            /*}
        }*/
    }
    fn handle_packet(&mut self, in_net: Ipv4Network, mut ethernet: MutableEthernetPacket) -> Result<()> {
        //let data_len = EthernetPacket::minimum_packet_size() + ethernet.payload().len();
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

                ip.set_ttl(ip.get_ttl() - 1);
                ip.set_checksum(ipv4::checksum(&ip.to_immutable()));

                if in_net.contains(dst_ip) {
                    debug!("ignoring packet that should be handled by kernel");
                    return Ok(());
                }

                let (out_net, mut hop) = self.routes.find_route(dst_ip)?;
                if out_net.contains(dst_ip) {
                    hop = dst_ip;
                }

                let dst_mac = self.arp_lookup((out_net, hop))?;
                let src_mac = self.arp_table[&out_net.ip()];
                ethernet.set_destination(dst_mac);
                ethernet.set_source(src_mac);
                
                debug!("forwarding {} byte ethernet packet from {} to {} via {}", ethernet.payload().len(), src_ip, dst_ip, out_net);
                self.interfaces.get_mut(&out_net).unwrap().tx.send_to(ethernet.packet(), None).unwrap()?;
                /*let ((dst_mac, next_hop, src_mac, src_iface), dst_ip, payload_size) = {
                    let ip_packet = match Ipv4Packet::new(ethernet.payload()) {
                        Some(p) => p,
                        None => {
                            warn!("received invalid ip packet on {} [mac: {}, dst mac: {}] from {}",
                                  in_net, self.arp_table[&in_net.ip()], ethernet.get_destination(), ethernet.get_source());
                            return Ok(());
                        },
                    };

                    let dst_ip = ip_packet.get_destination();
                    let payload_len = ip_packet.payload().len();
                    match self.find_ether_peers(ip_packet) {
                        Ok(peers) => (peers, dst_ip, payload_len),
                        Err(Error::DestinationReached(src_net)) => ((ethernet.get_destination(), dst_ip, ethernet.get_source(), self.interfaces.get_mut(&src_net).unwrap()), dst_ip, payload_len),
                        Err(e) => {
                            warn!("failed to find next ethernet peer: {}", e);
                            return Ok(());
                        },
                    }
                };

                ethernet.set_destination(dst_mac);
                ethernet.set_source(src_mac);
                ethernet.set_ethertype(EtherTypes::Ipv4);

                debug!("sending {} IP bytes to {} via {} ({}) from {} ({}))", payload_size, dst_ip, next_hop, dst_mac, &src_iface.name, src_mac);
                src_iface.tx.send_to(ethernet.packet(), None).unwrap()?;*/
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

        if !self.packet_queue.is_empty() {
            let mut queue = Vec::new();
            mem::swap(&mut queue, &mut self.packet_queue);
            for (iface_net, packet) in queue {
                self.handle_packet(iface_net, packet)?;
            }
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
        /*let mut data = read_to_bytes_mut(&mut self.tun, 65536)?;
        let payload_len = data.len();
        let mut ip_packet = MutableIpv4Packet::new(&mut data).expect("tun device provided invalid ip packet");
        let (next_src, next_hop) = match self.routes.find_route(ip_packet.get_destination()) {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to get route for packet to {}: {}", ip_packet.get_destination(), e);
                return Ok(());
            },
        };
        ip_packet.set_source(next_src.ip());
        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
        let ip_packet = ip_packet.to_immutable();

        let mtu = self.interfaces[&next_src].mtu;
        if payload_len > mtu as usize {
            return Err(Error::PacketTooLarge(data.len(), mtu));
        }

        let dst_mac = self.arp_lookup((next_src, next_hop))?;
        let src_mac = self.arp_table[&next_src.ip()];

        let mut ethernet = MutableEthernetPacket::owned(vec![0; mtu as usize + 18]).unwrap();
        ethernet.set_destination(dst_mac);
        ethernet.set_source(src_mac);
        ethernet.set_ethertype(EtherTypes::Ipv4);
        ethernet.set_payload(ip_packet.packet());
        let ethernet = ethernet.to_immutable();

        let src_iface = self.interfaces.get_mut(&next_src).unwrap();
        debug!("sending {} bytes to {} via {} ({}) from {} ({} [{}]))", ip_packet.payload().len(), ip_packet.get_destination(), next_hop, dst_mac, &src_iface.name, next_src, src_mac);
        src_iface.tx.send_to(&ethernet.packet()[..ethernet.packet_size() + data.len()], None).unwrap()?;*/
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
