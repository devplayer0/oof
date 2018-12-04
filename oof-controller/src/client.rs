use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::io::{Read, Write};
use std::net::{SocketAddr, Shutdown, TcpStream};

use log::{info, error};

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
            let clients = Arc::clone(clients);
            let mut socket = socket.try_clone().unwrap();
            thread::spawn(move || {
                let mut buf = [0; 4096];
                loop {
                    match socket.read(&mut buf) {
                        Ok(0) => {
                            info!("remote shutdown");
                            clients.lock().unwrap().remove(&addr);
                            break;
                        },
                        Ok(read) => {
                            info!("echoing {} bytes", read);
                            if let Err(e) = socket.write(&buf[..read]) {
                                error!("write error (from {}): {}", addr, e);
                            }
                        },
                        Err(e) => {
                            error!("read error (from {}): {}", addr, e);
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
