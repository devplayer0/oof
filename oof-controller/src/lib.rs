use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{Ordering, AtomicBool};
use std::thread::{self, JoinHandle};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, TcpListener};
use std::os::unix::io::AsRawFd;

use quick_error::quick_error;
use log::{info, error};
use nix::poll::{EventFlags, PollFd, poll};

mod client;

use crate::client::Client;

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
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Controller {
    running: Arc<AtomicBool>,
    clients: Arc<Mutex<HashMap<SocketAddr, Client>>>,
    thread: JoinHandle<()>,
}
impl Controller {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Result<Controller> {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        let listener_poll = PollFd::new(listener.as_raw_fd(), EventFlags::POLLIN);
        info!("bound on {}...", listener.local_addr()?);

        let running = Arc::new(AtomicBool::new(true));
        let clients = Arc::new(Mutex::new(HashMap::new()));
        let thread = {
            let running = Arc::clone(&running);
            let clients = Arc::clone(&clients);
            thread::spawn(move || {
                while running.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((socket, addr)) => {
                            info!("got connection from {}", addr);
                            clients.lock().unwrap().insert(addr, Client::new(socket, &clients));
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
            thread,
        })
    }

    pub fn stop(self) {
        self.running.store(false, Ordering::SeqCst);
        self.thread.join().expect("io thread panicked");

        let clients: Vec<_> = self.clients.lock().unwrap().drain().collect();
        for (_, client) in clients {
            client.shutdown();
        }
    }
}
