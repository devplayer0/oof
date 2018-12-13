use std::io::Read;
use std::net::{AddrParseError, IpAddr, SocketAddr, ToSocketAddrs};

use log::LevelFilter;
use bytes::{Bytes, BufMut, BytesMut};

use crate::{chk_disco, constants, Error, Result};

pub fn read_to_bytes_mut<R: Read>(stream: &mut R, count: usize) -> Result<BytesMut> {
    let mut data = BytesMut::with_capacity(count);
    Ok(unsafe {
        let read = chk_disco!(stream.read(&mut data.bytes_mut()[..count])?);
        data.advance_mut(read);
        data
    })
}
#[inline]
pub fn read_to_bytes<R: Read>(stream: &mut R, count: usize) -> Result<Bytes> {
    Ok(read_to_bytes_mut(stream, count)?.freeze())
}

pub fn parse_addr(addr: &str) -> std::result::Result<std::vec::IntoIter<SocketAddr>, AddrParseError> {
    if let Ok(a) = addr.to_socket_addrs() {
        return Ok(a);
    }

    Ok(vec![(addr.parse::<IpAddr>()?, constants::DEFAULT_PORT).into()].into_iter())
}
pub fn verbosity_to_log_level(verbosity: usize) -> LevelFilter {
    match verbosity {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        2 | _ => LevelFilter::Trace,
    }
}
