use std::io;
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::io::AsRawFd;

use quick_error::quick_error;
use ipnetwork::{IpNetworkError, Ipv4Network};
use nix::{libc, convert_ioctl_res, ioctl_read_bad};

use oof_common as common;
use oof_common::MessageType;

pub mod client;
pub mod raw;

ioctl_read_bad!(_bytes_available, libc::FIONREAD, libc::c_int);
pub fn bytes_available(socket: &TcpStream) -> Result<usize> {
    unsafe {
        let mut available = 0;
        _bytes_available(socket.as_raw_fd(), &mut available)?;
        Ok(available as usize)
    }
}

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

        InvalidRoute(err: IpNetworkError) {
            from()
            display("controller provided invalid route: {}", err)
            description("router provided invalid route")
            cause(err)
        }
        NoRoute(dst: Ipv4Addr) {
            display("controller has no route to {}", dst)
            description("controller has no route to this destination")
        }
        RouterOnly(t: MessageType) {
            description("received router only message")
            display("received router only message of type {}", t)
        }
        DefaultRoute {
            description("failed to add default route")
        }
        Mtu(iface: String) {
            display("failed to get mtu for interface: {}", iface)
            description("failed to get mtu for interface")
        }
        PacketTooLarge(size: usize, mtu: u32) {
            display("incoming packet bigger than mtu ({} > {})", size, mtu)
            description("incoming packet bigger than mtu")
        }
        DestinationReached(net: Ipv4Network) {}
    }
}
pub type Result<T> = std::result::Result<T, Error>;
