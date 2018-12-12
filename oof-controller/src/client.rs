use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::collections::HashMap;
use std::sync::{Arc, MutexGuard, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, Shutdown, TcpStream};
use std::os::unix::io::AsRawFd;

use enum_primitive::*;
use log::{debug, info, error};
use bufstream::BufStream;
use bytes::{IntoBuf, Buf, BufMut, BytesMut};
use ipnetwork::Ipv4Network;
use nix::poll::{EventFlags, PollFd, poll};

use crate::{Error, Result};
use oof_common as common;
use oof_common::MessageType;
use oof_common::util::read_to_bytes;
use oof_common::net::{LinkSpeed, Link, RoutingTable};
use crate::routing::Network;

#[derive(Debug)]
pub(crate) struct ClientInner {
    addr: SocketAddr,
    stream: BufStream<TcpStream>,
    clients: Arc<RwLock<HashMap<SocketAddr, Client>>>,
    network: Arc<RwLock<Network>>,
}
impl ClientInner {
    pub fn new(socket: TcpStream, clients: &Arc<RwLock<HashMap<SocketAddr, Client>>>, network: &Arc<RwLock<Network>>) -> ClientInner {
        let stream = BufStream::new(socket);
        ClientInner {
            addr: stream.get_ref().peer_addr().unwrap(),
            stream,
            clients: Arc::clone(clients),
            network: Arc::clone(network),
        }
    }
    pub fn start(&mut self) -> Result<()> {
        common::await_hello(&mut self.stream)?;
        common::send_hello(&mut self.stream)?;
        Ok(())
    }

    pub fn shutdown(&self) -> Result<()> {
        self.network.write().unwrap().remove_router(self.addr);
        self.stream.get_ref().shutdown(Shutdown::Both)?;
        Ok(())
    }

    fn send_invalidate_routes(&mut self) -> Result<()> {
        self.stream.write(&[ MessageType::InvalidateRoutes as u8 ])?;
        self.stream.flush()?;
        Ok(())
    }
    fn send_route(&mut self, net: Ipv4Network, hop: Ipv4Addr) -> Result<()> {
        let mut data = BytesMut::with_capacity(size_of::<u8>() + size_of::<u32>() + size_of::<u8>() + size_of::<u32>());
        data.put(MessageType::Route as u8);
        data.put_u32_be(net.network().into());
        data.put(net.prefix());
        data.put_u32_be(hop.into());

        self.stream.write(&data.freeze())?;
        self.stream.flush()?;
        Ok(())
    }
    fn send_no_route(&mut self, dst: Ipv4Addr) -> Result<()> {
        let mut data = BytesMut::with_capacity(size_of::<u8>() + size_of::<u32>());
        data.put(MessageType::NoRoute as u8);
        data.put_u32_be(dst.into());

        self.stream.write(&data.freeze())?;
        self.stream.flush()?;
        Ok(())
    }
    pub fn read_and_process(&mut self) -> Result<()> {
        use oof_common::MessageType::*;
        match common::read_message_type(&mut self.stream) {
            Ok(Hello) => return Err(common::Error::HelloAlready.into()),
            Ok(LinkInfo) => {
                let mut data = read_to_bytes(&mut self.stream, size_of::<u16>())?.into_buf();
                let count = data.get_u16_be();
                debug!("got {} links", count);
                if count == 0 {
                    return Ok(());
                }

                let list_size = count as usize * (size_of::<u32>() + size_of::<u8>() + size_of::<u8>());
                let mut data = read_to_bytes(&mut self.stream, list_size)?.into_buf();

                let mut links = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    let addr = Ipv4Addr::from(data.get_u32_be());
                    let net = Ipv4Network::new(addr, data.get_u8())?;
                    let speed = LinkSpeed::from_u8(data.get_u8()).ok_or(Error::BadLinkSpeed)?;
                    let link = Link::new(net, speed);

                    info!("{} link: {}", self.addr, link.network);
                    links.push(link);
                }

                let mut network = self.network.write().unwrap();
                network.update_router_links(self.addr, links);
                for (addr, client) in self.clients.read().unwrap().iter() {
                    if *addr == self.addr {
                        continue;
                    }

                    client.inner_mut().send_invalidate_routes()?;
                }
            },
            Ok(RouteRequest) => {
                let mut data = read_to_bytes(&mut self.stream, size_of::<u32>())?.into_buf();
                let dst = Ipv4Addr::from(data.get_u32_be());

                let route = match self.network.read().unwrap().routes(self.addr) {
                    None => None,
                    Some(r) => {
                        debug!("received route request for {} from {}", dst, self.addr);
                        match r.find_route(dst) {
                            None => None,
                            Some(r) => Some(r),
                        }
                    },
                };
                match route {
                    Some((net, hop)) => self.send_route(net, hop)?,
                    None => self.send_no_route(dst)?
                }
            },
            Ok(t) => return Err(Error::ControllerOnly(t)),
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Client {
    addr: SocketAddr,
    thread: JoinHandle<()>,
    inner: Arc<Mutex<ClientInner>>,
}
impl PartialEq for Client {
    fn eq(&self, other: &Client) -> bool {
        self.addr == other.addr
    }
}
impl Eq for Client {}
impl Hash for Client {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl Client {
    pub fn new(socket: TcpStream, clients: &Arc<RwLock<HashMap<SocketAddr, Client>>>, network: &Arc<RwLock<Network>>) -> Client {
        let addr = socket.peer_addr().unwrap();
        let inner = Arc::new(Mutex::new(ClientInner::new(socket.try_clone().unwrap(), clients, network)));
        let thread = {
            let inner = Arc::clone(&inner);
            let clients = Arc::clone(clients);
            thread::spawn(move || {
                {
                    let mut inner = inner.lock().unwrap();
                    match inner.start() {
                        Ok(i) => i,
                        Err(e) => {
                            error!("client {} failed to say hello: {}", addr, e);
                            if let Err(e) = inner.shutdown() {
                                error!("failed to close client {} socket: {}", addr, e);
                            }

                            clients.write().unwrap().remove(&addr);
                            return;
                        },
                    }
                }

                let socket_poll = PollFd::new(socket.as_raw_fd(), EventFlags::POLLIN);
                loop {
                    let _ = poll(&mut [socket_poll], -1);

                    let mut inner = inner.lock().unwrap();
                    match inner.read_and_process() {
                        Ok(()) => {},
                        Err(Error::Common(common::Error::SocketClosed)) => {
                            debug!("socket to {} closed", addr);
                            clients.write().unwrap().remove(&addr);
                            if let Err(e) = inner.shutdown() {
                                error!("failed to close client {} socket: {}", addr, e);
                            }

                            break;
                        },
                        Err(e) => {
                            error!("client {} error: {}", addr, e);
                            clients.write().unwrap().remove(&addr);
                            if let Err(e) = inner.shutdown() {
                                error!("failed to close client {} socket: {}", addr, e);
                            }

                            break;
                        },
                    }
                }
            })
        };

        Client {
            addr,
            thread,
            inner,
        }
    }

    pub fn inner_mut(&self) -> MutexGuard<ClientInner> {
        self.inner.lock().unwrap()
    }
    pub fn shutdown(self) {
        self.inner.lock().unwrap().shutdown().expect("failed to close socket");
        self.thread.join().expect("client thread panicked");
    }
}
