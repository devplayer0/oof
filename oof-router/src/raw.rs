use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread::{self, JoinHandle};
use std::io::Read;
use std::fs;
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::io::AsRawFd;

use log::{debug, error};
use ipnetwork::IpNetwork;
use nix::poll::{EventFlags, PollFd, poll};
use pnet::datalink;
use tun;

use oof_common::net::{LinkSpeed, Link};
use crate::{Error, Result, client};

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

pub struct RawRouter {
    running: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}
impl RawRouter {
    pub fn start<A: ToSocketAddrs, E: Fn(Error) + Send + 'static>(addr: A, err_handler: E) -> Result<RawRouter> {
        let routes = client::Router::connect(addr, err_handler)?;
        let ctl_ip = routes.addr().ip();

        let mut links = Vec::new();
        'outer: for iface in datalink::interfaces() {
            if !iface.is_up() || iface.is_loopback() {
                continue;
            }

            let mut addr = None;
            for net in iface.ips {
                match net {
                    IpNetwork::V6(_) => continue,
                    IpNetwork::V4(n) => match ctl_ip {
                        IpAddr::V4(a) if n.contains(a) => continue 'outer,
                        _ => addr = Some(n),
                    },
                }
            }

            if let Some(a) = addr {
                links.push(Link::new(a, iface_speed(&iface.name).unwrap_or(LinkSpeed::Gigabit)));
            }
        }

        let mut tun_dev = tun::create(tun::Configuration::default()
                                  .address("1.2.3.4")
                                  .netmask("255.255.255.255")
                                  .up())?;
        routes.update_links(links)?;

        let running = Arc::new(AtomicBool::new(true));
        let thread = {
            let running = Arc::clone(&running);
            thread::spawn(move || {
                let tun_poll = PollFd::new(tun_dev.as_raw_fd(), EventFlags::POLLIN);
                while running.load(Ordering::SeqCst) {
                    let _ = poll(&mut [tun_poll], 500);

                    let mut buf = [0; 65536];
                    match tun_dev.read(&mut buf) {
                        Ok(r) => debug!("read a packet from the tun device! ({}) bytes", r),
                        Err(e) => error!("tun read error: {}", e),
                    }
                }
                routes.stop();
            })
        };

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
