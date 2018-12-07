use std::ops::Deref;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::io;
use std::process::Command;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::os::unix::io::AsRawFd;

use log::{debug, warn, error};
use ipnetwork::{IpNetwork, Ipv4Network};
use bytes::{BufMut, BytesMut};
use nix::poll::{EventFlags, PollFd, poll};
use pnet::datalink::{self, MacAddr, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::packet::{PacketSize, Packet};
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use tun;

use oof_common::util::read_to_bytes_mut;
use oof_common::net::{LinkSpeed, Link, Route};
use crate::{Error, Result, client};

const MAGIC_IP: &str = "1.2.3.4";
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
pub fn iface_mtu(iface: &str) -> Option<u16> {
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
fn add_default_route(via: &str) -> Result<()> {
    let result = Command::new("ip")
        .args(&[ "route", "add", "default", "via", via ])
        .status()?;

    match result.success() {
        true => Ok(()),
        false => Err(Error::DefaultRoute),
    }
}

struct RawInterface {
    iface: NetworkInterface,
    mtu: u16,
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
    pub fn new(iface: NetworkInterface) -> Result<RawInterface> {
        let mut if_conf = datalink::Config::default();
        if_conf.read_timeout = Some(Duration::from_secs(1));
        let (tx, rx) = match datalink::channel(&iface, if_conf)? {
            datalink::Channel::Ethernet(tx, rx) => (tx, rx),
            _ => unreachable!(),
        };

        let mtu = iface_mtu(&iface.name).ok_or(Error::Mtu(iface.name.clone()))?;
        Ok(RawInterface {
            iface,
            mtu,
            tx,
            rx,
        })
    }
}

struct RawRouterInner {
    routes: client::Router,
    tun: Box<tun::Device>,
    tun_poll: PollFd,
    interfaces: HashMap<Ipv4Network, RawInterface>,
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
                match net {
                    IpNetwork::V6(_) => continue,
                    IpNetwork::V4(n) => match ctl_ip {
                        IpAddr::V4(a) if n.contains(a) => continue 'outer,
                        _ => addr = Some(*n),
                    },
                }
            }

            if let Some(a) = addr {
                links.push(Link::new(a, iface_speed(&iface.name).unwrap_or(LinkSpeed::Gigabit)));
                arp_table.insert(a.ip(), iface.mac.expect("iface has no mac address??"));
                interfaces.insert(a, iface);
            }
        }

        let tun_dev = tun::create(tun::Configuration::default()
                                  .address(MAGIC_IP)
                                  .netmask("255.255.255.255")
                                  .up())?;
        add_default_route(MAGIC_IP)?;
        routes.update_links(links)?;

        let tun_poll = PollFd::new(tun_dev.as_raw_fd(), EventFlags::POLLIN);
        let interfaces = {
            match interfaces.into_iter()
                .map(|(a, iface)| Ok((a, RawInterface::new(iface)?)))
                .collect() {
                Ok(i) => i,
                Err(e) => return Err(e),
            }
        };

        Ok(RawRouterInner {
            routes,
            tun: Box::new(tun_dev),
            tun_poll,
            interfaces,
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
            debug!("sending arp request");
            if start.elapsed() >= Duration::from_secs(3) {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "Timed out").into());
            }

            let packet = EthernetPacket::new(iface.rx.next()?).unwrap();
            if packet.get_ethertype() != EtherTypes::Arp {
                continue;
            }

            let packet = ArpPacket::new(packet.payload()).expect("invalid arp packet");
            if packet.get_operation() != ArpOperations::Reply ||
                packet.get_protocol_type() != EtherTypes::Ipv4 ||
                packet.get_target_hw_addr() != src_mac ||
                packet.get_target_proto_addr() != src.ip() ||
                packet.get_sender_proto_addr() != target {
                continue;
            }

            break packet.get_sender_hw_addr()
        };

        debug!("arp reply: {} -> {}", target, target_mac);
        self.arp_table.insert(target, target_mac);
        Ok(target_mac)
    }
    pub fn read_and_process(&mut self) -> Result<()> {
        match poll(&mut [self.tun_poll], 500) {
            Ok(0) => return Ok(()),
            _ => {},
        }

        let mut data = read_to_bytes_mut(&mut self.tun, 65536)?;
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
        src_iface.tx.send_to(&ethernet.packet()[..ethernet.packet_size() + data.len()], None).unwrap()?;
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
