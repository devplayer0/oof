#![feature(const_slice_len)]

use std::fmt::{self, Display};
use std::io::{self, Read, Write};
use std::net::TcpStream;

use quick_error::quick_error;
use enum_primitive::*;
use bytes::{BufMut, BytesMut};
use bufstream::BufStream;

pub mod constants;
pub mod util;
pub mod net;

#[macro_export]
macro_rules! chk_disco {
    ($r: expr) => {{
        let r = $r;
        if r == 0 {
            return Err(Error::SocketClosed);
        }
        r
    }}
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

        SocketClosed {}
        InvalidType(t: u8) {
            description("invalid message type")
            display("invalid message type: {}", t)
        }
        MalformedMessage(t: MessageType) {
            description("malformed message")
            display("malformed {} message", t)
        }
        HelloTimeout {
            description("timed out waiting for HELLO")
        }
        NoHello(t: MessageType) {
            description("haven't said hello")
            display("can't accept {} message, haven't said hello", t)
        }
        HelloAlready {
            description("already said hello")
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

enum_from_primitive! {
    #[derive(Debug, PartialEq)]
    pub enum MessageType {
        Hello = 0,
        LinkInfo = 1,
        RouteRequest = 2,
        Route = 3,
        NoRoute = 4,
        InvalidateRoutes = 5,
    }
}
impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use crate::MessageType::*;
        write!(f, "{}", match self {
            Hello => "HELLO",
            LinkInfo => "LINK_INFO",
            RouteRequest => "ROUTE_REQUEST",
            Route => "ROUTE",
            NoRoute => "NO_ROUTE",
            InvalidateRoutes => "INVALIDATE_ROUTES",
        })
    }
}
pub fn read_message_type(stream: &mut BufStream<TcpStream>) -> Result<MessageType> {
    let mut t = [0; 1];
    chk_disco!(stream.read(&mut t)?);
    let t = t[0];

    match MessageType::from_u8(t) {
        Some(t) => Ok(t),
        None => Err(Error::InvalidType(t)),
    }
}

pub fn await_hello(stream: &mut BufStream<TcpStream>) -> Result<()> {
    stream.get_ref().set_read_timeout(Some(constants::HELLO_TIMEOUT))?;
    match read_message_type(stream) {
        Ok(MessageType::Hello) => {
            let mut buf = [0; constants::HELLO_MAGIC.len()];
            chk_disco!(match stream.read(&mut buf) {
                Ok(r) => r,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Err(Error::HelloTimeout),
                Err(e) => return Err(e.into()),
            });
            if buf != constants::HELLO_MAGIC {
                return Err(Error::MalformedMessage(MessageType::Hello));
            }
        },
        Ok(t) => return Err(Error::NoHello(t)),
        Err(Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => return Err(Error::HelloTimeout),
        Err(e) => return Err(e),
    }
    stream.get_ref().set_read_timeout(None)?;

    Ok(())
}
pub fn send_hello(stream: &mut BufStream<TcpStream>) -> Result<()> {
    let mut data = BytesMut::with_capacity(5);
    data.put_u8(MessageType::Hello as u8);
    data.put(constants::HELLO_MAGIC);

    stream.write_all(&data.freeze())?;
    stream.flush()?;
    Ok(())
}
