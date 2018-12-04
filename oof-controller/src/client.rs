use std::hash::{Hash, Hasher};
use std::mem::size_of;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::net::{Ipv4Addr, SocketAddr, Shutdown, TcpStream};

use log::{debug, info, error};
use bufstream::BufStream;
use bytes::{IntoBuf, Buf};
use ipnetwork::Ipv4Network;

use crate::{Error, Result};
use oof_common as common;
use oof_common::util::read_to_bytes;

#[derive(Debug)]
struct ClientInner {
    addr: SocketAddr,
    stream: BufStream<TcpStream>,
}
impl ClientInner {
    pub fn new(socket: TcpStream) -> Result<ClientInner> {
        let mut stream = BufStream::new(socket);
        common::await_hello(&mut stream)?;
        common::send_hello(&mut stream)?;

        Ok(ClientInner {
            addr: stream.get_ref().peer_addr().unwrap(),
            stream,
        })
    }

    pub fn socket(&self) -> &TcpStream {
        self.stream.get_ref()
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

                let list_size = count as usize * (size_of::<u32>() + size_of::<u8>());
                let mut data = read_to_bytes(&mut self.stream, list_size)?.into_buf();

                let mut links = Vec::new();
                for _ in 0..count {
                    let addr = Ipv4Addr::from(data.get_u32_be());
                    let network = Ipv4Network::new(addr, data.get_u8())?;

                    info!("{} has a link to {}", self.addr, network);
                    links.push(network);
                }
            },
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Client {
    addr: SocketAddr,
    thread: JoinHandle<()>,
    socket: TcpStream,
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
    pub fn new(socket: TcpStream, clients: &Arc<Mutex<HashMap<SocketAddr, Client>>>) -> Client {
        let addr = socket.peer_addr().unwrap();
        let thread = {
            let socket = socket.try_clone().unwrap();
            let clients = Arc::clone(clients);
            thread::spawn(move || {
                let mut inner = match ClientInner::new(socket.try_clone().unwrap()) {
                    Ok(i) => i,
                    Err(e) => {
                        error!("client {} failed to say hello: {}", addr, e);
                        if let Err(e) = socket.shutdown(Shutdown::Both) {
                            error!("failed to close client {} socket: {}", addr, e);
                        }

                        clients.lock().unwrap().remove(&addr);
                        return;
                    },
                };
                drop(socket);

                loop {
                    match inner.read_and_process() {
                        Ok(()) => {},
                        Err(Error::Common(common::Error::SocketClosed)) => {
                            debug!("socket to {} closed", addr);
                            clients.lock().unwrap().remove(&addr);
                            break;
                        },
                        Err(e) => {
                            error!("client {} error: {}", addr, e);
                            if let Err(e) = inner.socket().shutdown(Shutdown::Both) {
                                error!("failed to close client {} socket: {}", addr, e);
                            }

                            clients.lock().unwrap().remove(&addr);
                            break;
                        },
                    }
                }
            })
        };

        Client {
            addr,
            thread,
            socket,
        }
    }

    pub fn shutdown(self) {
        self.socket.shutdown(Shutdown::Both).expect("failed to close socket");
        self.thread.join().expect("client thread panicked");
    }
}
