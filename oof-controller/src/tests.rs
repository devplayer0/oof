use std::fs;

use oof_common::net::{LinkSpeed, Link};
use crate::routing::RouteManager;

macro_rules! addr {
    ($addr:expr) => ($addr.parse().expect("failed to parse address"))
}
macro_rules! links {
    ($($net:expr, $speed:ident),*) => (
        vec![$(
                Link::new(addr!($net), LinkSpeed::$speed),
        )*]
    )
}
#[test]
fn routing_graph() {
    let mut manager = RouteManager::new();
    manager.add_router(
        addr!("127.0.0.1:1234"),
        links!(
            "10.10.0.1/16", TenGigabit,
            "172.16.0.1/24", TenGigabit,
            "10.1.0.1/24", Gigabit,
            "10.123.123.1/24", Slow
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1235"),
        links!(
            "10.10.0.2/16", TenGigabit,
            "10.0.0.1/24", Gigabit
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1236"),
        links!(
            "10.1.0.2/24", Gigabit,
            "10.0.0.2/24", Gigabit,
            "10.60.0.1/30", TenGigabit
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1237"),
        links!(
            "172.16.0.2/24", TenGigabit,
            "10.60.0.2/30", TenGigabit,
            "10.2.0.1/24", Gigabit,
            "10.40.0.1/24", Gigabit
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1238"),
        links!(
            "10.40.0.2/24", Gigabit
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1239"),
        links!(
            "10.2.0.2/24", Gigabit,
            "172.24.0.1/24", Fast
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1240"),
        links!(
            "172.24.0.2/24", Slow,
            "10.123.123.2/24", Slow
        )
    );
    manager.add_router(
        addr!("127.0.0.1:1241"),
        links!(
            "10.10.0.3/16", Gigabit
        )
    );

    fs::write("/tmp/net.dot", format!("{}", manager.as_dot()));
}
