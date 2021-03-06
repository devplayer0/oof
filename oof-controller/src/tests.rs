use std::fs;

use oof_common::net::{LinkSpeed, Link};
use crate::routing::Network;

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

fn test_network() -> Network {
    let mut network = Network::new();
    network.update_router_links(
        addr!("127.0.0.1:1234"),
        links!(
            "10.1.0.1/24", TenGigabit,
            "10.0.0.2/16", TenGigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1235"),
        links!(
            "10.0.0.1/16", Gigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1236"),
        links!(
            "10.2.0.1/24", TenGigabit,
            "10.0.0.3/16", TenGigabit
        )
    );
    /*network.update_router_links(
        addr!("127.0.0.1:1234"),
        links!(
            "10.10.0.1/16", TenGigabit,
            "172.16.0.1/24", TenGigabit,
            "10.1.0.1/24", Gigabit,
            "10.123.123.1/24", Slow
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1235"),
        links!(
            "10.10.0.2/16", TenGigabit,
            "10.0.0.1/24", Gigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1236"),
        links!(
            "10.1.0.2/24", Gigabit,
            "10.0.0.2/24", Gigabit,
            "10.60.0.1/30", TenGigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1237"),
        links!(
            "172.16.0.2/24", TenGigabit,
            "10.60.0.2/30", TenGigabit,
            "10.2.0.1/24", Gigabit,
            "10.40.0.1/24", Gigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1238"),
        links!(
            "10.40.0.2/24", Gigabit
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1239"),
        links!(
            "10.2.0.2/24", Gigabit,
            "172.24.0.1/24", Fast
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1240"),
        links!(
            "172.24.0.2/24", Fast,
            "10.123.123.2/24", Fast
        )
    );
    network.update_router_links(
        addr!("127.0.0.1:1241"),
        links!(
            "10.10.0.3/16", Gigabit
        )
    );*/

    network
}
#[test]
fn routing_graph() {
    let net = test_network();
    fs::write("/tmp/net.dot", format!("{}", net.as_dot())).unwrap();
}

fn print_table(net: &Network, router: &str) {
    println!("table for {}", router);
    for (net, next_hop) in net.routes(addr!(router)).expect("failed to get routing table").iter() {
        println!("{} via {}", net, next_hop);
    }
}
#[test]
fn routing_table() {
    let net = test_network();
    print_table(&net, "127.0.0.1:1234");
    print_table(&net, "127.0.0.1:1235");
    print_table(&net, "127.0.0.1:1236");
}
