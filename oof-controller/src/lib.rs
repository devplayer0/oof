use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread::{self, JoinHandle};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, TcpListener};
use std::os::unix::io::AsRawFd;

use quick_error::quick_error;
use log::{info, error};
use nix::poll::{EventFlags, PollFd, poll};
use ipnetwork::IpNetworkError;

mod routing;
mod client;

use oof_common as common;
use oof_common::MessageType;
use crate::client::Client;
use crate::routing::Network;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: io::Error) {
            from()
            display("io error: {}", err)
            description(err.description())
            cause(err)
        }
        Unix(err: nix::Error) {
            from()
            display("os error: {}", err)
            description(err.description())
            cause(err)
        }
        Common(err: common::Error) {
            from()
            display("{}", err)
            description(err.description())
            cause(err)
        }

        InvalidLink(err: IpNetworkError) {
            from()
            display("router provided invalid link: {}", err)
            description("router provided invalid link")
            cause(err)
        }
        BadLinkSpeed {
            description("router provided invalid link speed")
        }
        ControllerOnly(t: MessageType) {
            description("received controller only message")
            display("received controller only message of type {}", t)
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Controller {
    running: Arc<AtomicBool>,
    clients: Arc<RwLock<HashMap<SocketAddr, Client>>>,
    network: Arc<RwLock<Network>>,
    thread: JoinHandle<()>,
}
impl Controller {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Controller> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let listener_poll = PollFd::new(listener.as_raw_fd(), EventFlags::POLLIN);
        info!("bound on {}...", listener.local_addr()?);

        let running = Arc::new(AtomicBool::new(true));
        let clients = Arc::new(RwLock::new(HashMap::new()));
        let network = Arc::new(RwLock::new(Network::new()));
        let thread = {
            let running = Arc::clone(&running);
            let clients = Arc::clone(&clients);
            let network = Arc::clone(&network);
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, addr)) => {
                            info!("got connection from {}", addr);
                            clients.write().unwrap().insert(addr, Client::new(socket, &clients, &network));
                        },
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            let _ = poll(&mut [listener_poll], 500);
                        },
                        Err(e) => error!("socket accept error: {}", e),
                    }
                }
            })
        };

        Ok(Controller {
            running,
            clients,
            network,
            thread,
        })
    }

    pub fn net_as_dot(&self) -> String {
        format!("{}", self.network.read().unwrap().as_dot())
    }
    pub fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        self.thread.join().expect("io thread panicked");

        let clients: Vec<_> = self.clients.write().unwrap().drain().collect();
        for (_, client) in clients {
            client.shutdown();
        }
    }
}

#[cfg(test)]
mod tests;
