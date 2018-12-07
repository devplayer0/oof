use std::mem::size_of;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{self, SyncSender, Receiver};
use std::thread::{self, JoinHandle};
use std::io::Write;
use std::net::{Ipv4Addr, ToSocketAddrs, SocketAddr, Shutdown, TcpStream};
use std::os::unix::io::AsRawFd;

use log::error;
use bufstream::BufStream;
use bytes::{IntoBuf, Buf, BufMut, BytesMut};
use ipnetwork::{IpNetworkError, Ipv4Network};
use nix::poll::{EventFlags, PollFd, poll};

use oof_common as common;
use oof_common::MessageType;
use oof_common::util::read_to_bytes;
use oof_common::net::{Link, Route, RoutingTable};
use crate::{Error, Result};

#[derive(Debug)]
struct RouterInner {
    stream: BufStream<TcpStream>,
    links: Vec<Link>,
    routes: HashMap<Ipv4Network, Ipv4Addr>,
    route_tx: SyncSender<Result<Route>>,
}
impl RouterInner {
    pub fn new(socket: TcpStream) -> Result<(RouterInner, Receiver<Result<Route>>)> {
        let mut stream = BufStream::new(socket);
        common::send_hello(&mut stream)?;
        common::await_hello(&mut stream)?;

        let (route_tx, route_rx) = mpsc::sync_channel(0);
        Ok((RouterInner {
            stream,
            links: Vec::new(),
            routes: HashMap::new(),
            route_tx,
        }, route_rx))
    }

    pub fn update_links(&mut self, links: Vec<Link>) -> Result<()> {
        let list_size = links.len() * (size_of::<u32>() + size_of::<u8>() + size_of::<u8>());
        let mut data = BytesMut::with_capacity(size_of::<u8>() + size_of::<u16>() + list_size);
        data.put_u8(MessageType::LinkInfo as u8);
        data.put_u16_be(links.len() as u16);

        for link in &links {
            data.put_u32_be(link.network.ip().into());
            data.put_u8(link.network.prefix());
            data.put_u8(link.speed as u8);
        }

        self.stream.write(&data.freeze())?;
        self.stream.flush()?;
        self.links = links;
        Ok(())
    }
    pub fn find_route(&mut self, dst: Ipv4Addr) -> Result<Option<Route>> {
        match self.routes.find_route(dst) {
            Some(r) => Ok(Some(r)),
            None => {
                let mut data = BytesMut::with_capacity(size_of::<u8>() + size_of::<u32>());
                data.put(MessageType::RouteRequest as u8);
                data.put_u32_be(dst.into());

                self.stream.write(&data.freeze())?;
                self.stream.flush()?;
                Ok(None)
            },
        }
    }
    pub fn read_and_process(&mut self) -> Result<()> {
        use oof_common::MessageType::*;
        match common::read_message_type(&mut self.stream) {
            Ok(Hello) => return Err(common::Error::HelloAlready.into()),
            Ok(Route) => {
                let mut data = read_to_bytes(&mut self.stream, size_of::<u32>())?.into_buf();
                let hop = Ipv4Addr::from(data.get_u32_be());

                for link in &self.links {
                    if link.network.contains(hop) {
                        self.routes.insert(link.network, hop);
                        self.route_tx.send(Ok((link.network, hop))).unwrap();
                        return Ok(());
                    }
                }
                return Err(Error::InvalidRoute(IpNetworkError::InvalidAddr(hop.to_string())));
            },
            Ok(NoRoute) => {
                let mut data = read_to_bytes(&mut self.stream, size_of::<u32>())?.into_buf();
                let addr = Ipv4Addr::from(data.get_u32_be());
                self.route_tx.send(Err(Error::NoRoute(addr))).unwrap();
            },
            Ok(InvalidateRoutes) => self.routes.clear(),
            Ok(t) => return Err(Error::RouterOnly(t)),
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }
    pub fn shutdown(&self) -> Result<()> {
        self.stream.get_ref().shutdown(Shutdown::Both)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Router {
    addr: SocketAddr,
    inner: Arc<Mutex<RouterInner>>,
    route_rx: Receiver<Result<Route>>,
    thread: JoinHandle<()>,
}
impl Router {
    pub fn connect<A: ToSocketAddrs, E: Fn(Error) + Send + 'static>(addr: A, err_handler: E) -> Result<Router> {
        let socket = TcpStream::connect(addr)?;
        let addr = socket.peer_addr()?;
        let (inner, route_rx) = RouterInner::new(socket.try_clone().unwrap())?;
        let inner = Arc::new(Mutex::new(inner));

        let thread = {
            let inner = Arc::clone(&inner);
            thread::spawn(move || {
                let socket_poll = PollFd::new(socket.as_raw_fd(), EventFlags::POLLIN);
                loop {
                    match poll(&mut [socket_poll], 500) {
                        Ok(0) => continue,
                        _ => {},
                    }

                    let mut inner = inner.lock().unwrap();
                    match inner.read_and_process() {
                        Ok(()) => {},
                        Err(e@Error::Common(common::Error::SocketClosed)) => {
                            err_handler(e);
                            break;
                        },
                        Err(e) => {
                            err_handler(e);
                            if let Err(e) = inner.shutdown() {
                                error!("failed to close socket: {}", e);
                            }

                            break;
                        },
                    }
                }
            })
        };
        Ok(Router {
            addr,
            inner,
            route_rx,
            thread,
        })
    }

    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    #[inline]
    pub fn update_links(&self, links: Vec<Link>) -> Result<()> {
        self.inner.lock().unwrap().update_links(links)
    }
    pub fn find_route(&self, dst: Ipv4Addr) -> Result<Route> {
        let mut inner = self.inner.lock().unwrap();
        match inner.find_route(dst) {
            Err(e) => Err(e),
            Ok(Some(r)) => Ok(r),
            Ok(None) => {
                drop(inner);
                self.route_rx.recv().unwrap()
            },
        }
    }
    pub fn stop(self) {
        self.inner.lock().unwrap().shutdown().expect("failed to close socket");
        self.thread.join().expect("io thread panicked");
    }
}
