use std::collections::HashMap;
use std::net::SocketAddr;

use ipnetwork::Ipv4Network;
use petgraph::graph::{NodeIndex, Graph};
#[cfg(test)]
use petgraph::dot::Dot;

use oof_common::net::Link;

const REFERENCE_SPEED: u32 = 1000;
pub fn link_cost(link: Link) -> f64 {
    REFERENCE_SPEED as f64 / link.speed.value() as f64
}

struct Router {
    node_index: NodeIndex,
    links: HashMap<Ipv4Network, Link>,
}
impl Router {
    pub fn new(node_index: NodeIndex, links: Vec<Link>) -> Router {
        let mut map = HashMap::new();
        for link in links {
            // get a network whose ip is the lowest in the network for matching purposes
            let net = Ipv4Network::new(link.network.network(), link.network.prefix()).unwrap();
            map.insert(net, link);
        }

        Router {
            node_index,
            links: map,
        }
    }

    pub fn update_edges(&self, routers: &HashMap<SocketAddr, Router>, network: &mut Graph<SocketAddr, Link>) {
        for (net, link) in &self.links {
            for other in routers.values() {
                if other.node_index == self.node_index {
                    continue;
                }

                if other.links.contains_key(&net) {
                    network.update_edge(self.node_index, other.node_index, *link);
                }
            }
        }
    }
}

pub(crate) struct RouteManager {
    routers: HashMap<SocketAddr, Router>,
    network: Graph<SocketAddr, Link>,
}
impl RouteManager {
    pub fn new() -> RouteManager {
        RouteManager {
            routers: HashMap::new(),
            network: Graph::new(),
        }
    }

    pub fn add_router(&mut self, mgmt_addr: SocketAddr, links: Vec<Link>) -> bool {
        if self.routers.contains_key(&mgmt_addr) {
            return false;
        }

        let new = Router::new(self.network.add_node(mgmt_addr), links);
        self.routers.insert(mgmt_addr, new);
        for router in self.routers.values() {
            router.update_edges(&self.routers, &mut self.network);
        }

        true
    }

    #[cfg(test)]
    pub fn as_dot(&self) -> Dot<&Graph<SocketAddr, Link>> {
        Dot::new(&self.network)
    }
}
