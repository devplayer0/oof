use std::time::Duration;

pub const DEFAULT_PORT: u16 = 27999;

pub const HELLO_MAGIC: &'static [u8] = b"Oof";
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
