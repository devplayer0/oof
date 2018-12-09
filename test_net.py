#!/usr/bin/env python
import time
import signal
import argparse
import ipaddress

import yaml
import pyroute2

class TestNet:
    def __init__(self, conf):
        self.conf = conf
        self.main_db = pyroute2.IPDB()
        self.networks = {}
        self.nodes = conf['nodes']

    def start(self):
        for name, net in self.conf['networks'].items():
            net = ipaddress.ip_network(net)
            for existing in self.networks.values():
                if net.overlaps(existing['net']):
                    raise Exception('network {} overlaps with existing network {}'.format(net, existing['net']))

            print('creating network {} ({})'.format(name, net))
            self.networks[name] = {
                'net': net,
                'used_ips': set(),
                'bridge': self.main_db
                            .create(kind='bridge', ifname='{}-sw'.format(name))
                            .up()
                            .commit(),
            }

        for name, node in self.nodes.items():
            if name in pyroute2.netns.listnetns():
                raise Exception('[{}] network namespace already exists'.format(name))

            print('creating node "{}"'.format(name))
            node['ns'] = pyroute2.NetNS(name)
            node['db'] = pyroute2.IPDB(nl=node['ns'])
            with node['db'].interfaces['lo'] as lo:
                lo.up()

            for net_name, net in node['networks'].items():
                dest = self.networks[net_name]
                if 'ip' in net:
                    net['ip'] = ipaddress.IPv4Interface((net['ip'], dest['net'].prefixlen))
                    if net['ip'].ip not in dest['net']:
                        raise Exception('[{}] ip address {} is not in network {} ({})'.format(name, net['ip'].ip, net_name, dest['net']))
                    if net['ip'].ip in dest['used_ips']:
                        raise Exception('[{}] ip address {} is already in use in network {}'.format(name, net['ip'].ip, net_name))

                    dest['used_ips'].add(net['ip'].ip)
                else:
                    net['ip'] = self.next_ip(net_name)

                print('[{}] adding to network {} (ip: {})'.format(name, net_name, net['ip']))
                host_connector = (self.main_db
                                    .create(ifname='{}-{}'.format(name, net_name), kind='veth', peer=net_name)
                                    .up()
                                    .commit())
                (dest['bridge']
                    .add_port(host_connector)
                    .commit())

                with self.main_db.interfaces[net_name] as nc:
                    nc.net_ns_fd = name
                time.sleep(0.2)

                with node['db'].interfaces[net_name] as nc:
                    nc.up()
                    nc.add_ip(str(net['ip']))

    def next_ip(self, net):
        network = self.networks[net]
        for ip in network['net'].hosts():
            if ip not in network['used_ips']:
                return ipaddress.IPv4Interface((ip, network['net'].prefixlen))

        raise Exception('network {} ({}) is full'.format(net, network['net']))

    def close(self):
        for node in self.nodes.values():
            if 'ns' in node:
                node['ns'].remove()
                node['ns'].close()
            if 'db' in node:
                node['db'].release()

        for net in self.networks.values():
            (net['bridge']
                .remove()
                .commit())
        self.main_db.release()

def main():
    parser = argparse.ArgumentParser(description='manage "networks" (via network namespaces, veth pairs and bridges) for testing')
    parser.add_argument('configuration', help='YAML file containing networks and network nodes')

    args = parser.parse_args()
    with open(args.configuration) as conf_file:
        config = yaml.load(conf_file)

    net = TestNet(config)
    try:
        net.start()
    except Exception as ex:
        net.close()
        raise ex

    signal.sigwait([signal.SIGINT, signal.SIGTERM])
    print('cleaning up...')
    net.close()

if __name__ == "__main__":
    main()
