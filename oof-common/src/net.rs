use std::fmt::{self, Display};
use std::net::Ipv4Addr;

use enum_primitive::*;
use ipnetwork::Ipv4Network;

enum_from_primitive! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    pub enum LinkSpeed {
        Slow = 0,
        Fast = 1,
        Gigabit = 2,
        TenGigabit = 3,
        FortyGigabit = 4,
        HundredGigabit = 5,
    }
}
impl LinkSpeed {
    pub fn value(&self) -> u32 {
        use self::LinkSpeed::*;
        match self {
            Slow => 10,
            Fast => 100,
            Gigabit => 1000,
            TenGigabit => 10000,
            FortyGigabit => 40000,
            HundredGigabit => 100000,
        }
    }
}
impl Display for LinkSpeed {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LinkSpeed::*;
        write!(f, "{}", match self {
            Slow => "10Mbps",
            Fast => "100Mbps",
            Gigabit => "1Gbps",
            TenGigabit => "10Gbps",
            FortyGigabit => "40Gbps",
            HundredGigabit => "100Gbps",
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Link {
    pub network: Ipv4Network,
    pub speed: LinkSpeed,
}
impl Default for Link {
    fn default() -> Link {
        Link {
            network: Ipv4Network::new(Ipv4Addr::LOCALHOST, 32).unwrap(),
            speed: LinkSpeed::TenGigabit,
        }
    }
}
impl Display for Link {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} @ {}", self.network, self.speed)
    }
}
impl Link {
    pub fn new(network: Ipv4Network, speed: LinkSpeed) -> Link {
        Link {
            network,
            speed,
        }
    }
}
