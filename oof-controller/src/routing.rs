use std::ops::Add;
use std::cmp::{Ordering, Reverse};
use std::fmt::{self, Display};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use ipnetwork::Ipv4Network;
use priority_queue::PriorityQueue;
use petgraph::visit::EdgeRef;
use petgraph::graph::{NodeIndex, Graph};

use oof_common::constants;
use oof_common::net::Link;

#[cfg(test)]
use petgraph::dot::Dot;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
struct Cost(f64);
impl From<f64> for Cost {
    fn from(c: f64) -> Cost {
        assert!(!c.is_nan());
        Cost(c)
    }
}
impl Add for Cost {
    type Output = Cost;
    fn add(self, other: Cost) -> Cost {
        Cost::from(self.0 + other.0)
    }
}
impl Eq for Cost {}
impl Ord for Cost {
    fn cmp(&self, other: &Cost) -> Ordering {
        self.0.partial_cmp(&other.0).unwrap_or(Ordering::Equal)
    }
}

trait Costable {
    fn cost(&self) -> Cost;
}
impl Costable for Link {
    fn cost(&self) -> Cost {
        (constants::REFERENCE_BANDWIDTH as f64 / self.speed.value() as f64).into()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Node {
    Network(Ipv4Network),
    Router(SocketAddr),
}
impl Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Node::*;
        match self {
            Network(n) => write!(f, "{}", n),
            Router(r) => write!(f, "{}", r),
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct DijkstraInfo {
    cost: Cost,
    prev: Option<NodeIndex>,
}
impl Default for DijkstraInfo {
    fn default() -> DijkstraInfo {
        DijkstraInfo {
            cost: std::f64::INFINITY.into(),
            prev: None,
        }
    }
}

#[derive(Debug)]
struct Router {
    node_index: NodeIndex,
    links: HashMap<Ipv4Network, Link>,
}
impl Router {
    pub fn new(node_index: NodeIndex) -> Router {
        Router {
            node_index,
            links: HashMap::new(),
        }
    }

    pub fn update_links(&mut self, links: Vec<Link>) {
        self.links.clear();
        for link in links {
            // get a network whose ip is the lowest in the network for matching purposes
            let net = Ipv4Network::new(link.network.network(), link.network.prefix()).unwrap();
            self.links.insert(net, link);
        }
    }
    pub fn update_network(&self, networks: &mut HashMap<Ipv4Network, NodeIndex>, network: &mut Graph<Node, Link, petgraph::Undirected>) {
        for (net, link) in &self.links {
            if !networks.contains_key(net) {
                let new = network.add_node(Node::Network(*net));
                networks.insert(*net, new);
            }
            network.update_edge(self.node_index, networks[net], *link);
        }
    }
    pub fn calculate_routes(&self, networks: &HashMap<Ipv4Network, NodeIndex>, routers: &HashMap<SocketAddr, Router>, network: &Graph<Node, Link, petgraph::Undirected>) -> HashMap<Ipv4Network, Ipv4Addr> {
        let mut infos = HashMap::new();
        let mut unvisited: PriorityQueue<_, Reverse<Cost>> = networks.values()
            .map(|i| (*i, Reverse(std::f64::INFINITY.into())))
            .chain(
                routers.values()
                .map(|r| (r.node_index, match r.node_index {
                    i if i == self.node_index => Reverse(0f64.into()),
                    _ => Reverse(std::f64::INFINITY.into()),
                }))
            ).collect();
        for (i, _) in &unvisited {
            let mut info = DijkstraInfo::default();
            if *i == self.node_index {
                info.cost = 0f64.into();
            }

            infos.insert(*i, info);
        }

        while !unvisited.is_empty() {
            let (closest, _) = unvisited.pop().unwrap();
            for link in network.edges(closest) {
                assert!(link.source() == closest);
                let cost = infos[&closest].cost + link.weight().cost();

                let mut neighbor_info = infos.get_mut(&link.target()).unwrap();
                if cost < neighbor_info.cost {
                    neighbor_info.cost = cost;
                    neighbor_info.prev = Some(closest);
                    unvisited.change_priority(&link.target(), Reverse(cost));
                }
            }
        }

        let mut routes = HashMap::new();
        let networks: Vec<_> = infos.iter()
            .filter_map(|(index, info)| match info.prev {
                None => None,
                Some(p) => match network[*index] {
                    //Node::Network(n) if self.links.contains_key(&n) => None,
                    Node::Network(n) => Some((p, n)),
                    Node::Router(_) => None,
                }
            })
            .collect();
        for (mut prev, net) in networks {
            let mut next_hop = None;
            while prev != self.node_index {
                let hop = match network[prev] {
                    Node::Router(r) => r,
                    Node::Network(_) => unreachable!(),
                };
                prev = infos[&prev].prev.unwrap();

                let hop_net = match network[prev] {
                    Node::Network(n) => n,
                    Node::Router(_) => unreachable!(),
                };
                next_hop = Some(routers[&hop].links[&hop_net].network.ip());
                prev = infos[&prev].prev.unwrap();
            }

            if let Some(h) = next_hop {
                routes.insert(net, h);
            }
        }
        routes
    }
}

pub trait RoutingTable {
    fn find_route(&self, addr: Ipv4Addr) -> Option<(Ipv4Network, Ipv4Addr)>;
}
impl RoutingTable for HashMap<Ipv4Network, Ipv4Addr> {
    fn find_route(&self, addr: Ipv4Addr) -> Option<(Ipv4Network, Ipv4Addr)> {
        for (net, hop) in self {
            if net.contains(addr) {
                return Some((*net, *hop));
            }
        }
        None
    }
}

#[derive(Debug)]
pub(crate) struct Network {
    networks: HashMap<Ipv4Network, NodeIndex>,
    routers: HashMap<SocketAddr, Router>,
    network: Graph<Node, Link, petgraph::Undirected>,
    routes: HashMap<SocketAddr, HashMap<Ipv4Network, Ipv4Addr>>,
}
impl Network {
    pub fn new() -> Network {
        Network {
            networks: HashMap::new(),
            routers: HashMap::new(),
            network: Graph::new_undirected(),
            routes: HashMap::new(),
        }
    }

    pub fn update_router_links(&mut self, mgmt_addr: SocketAddr, links: Vec<Link>) {
        if !self.routers.contains_key(&mgmt_addr) {
            let new = Router::new(self.network.add_node(Node::Router(mgmt_addr)));
            self.routers.insert(mgmt_addr, new);
        }
        self.routers.get_mut(&mgmt_addr).unwrap().update_links(links);

        for router in self.routers.values() {
            router.update_network(&mut self.networks, &mut self.network);
        }
        self.routes.clear();
        for (mgmt_addr, router) in &self.routers {
            let table = router.calculate_routes(&self.networks, &self.routers, &self.network);
            self.routes.insert(*mgmt_addr, table);
        }
    }
    pub fn routes(&self, mgmt_addr: SocketAddr) -> Option<&HashMap<Ipv4Network, Ipv4Addr>> {
        self.routes.get(&mgmt_addr)
    }

    #[cfg(test)]
    pub fn as_dot(&self) -> Dot<&Graph<Node, Link, petgraph::Undirected>> {
        Dot::new(&self.network)
    }
}
