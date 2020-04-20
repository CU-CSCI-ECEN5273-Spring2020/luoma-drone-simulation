#!/usr/bin/python

from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink # need to import after mininet.node due to circular imports
from mininet.net import Mininet
from mininet.topo import Topo

import os

"""
########
Topologies
########
"""
# Each host is connected to its own switch
# The switches are connected in a chain with a number of switches/host pairs = count
# modified from https://github.com/mininet/mininet/wiki/Introduction-to-Mininet
class ChainTopo(Topo):
    def build(self, count=3):
        # as configured, can currently only handle up to 9 hosts due to the way mac is formatted
        # the ip and mac configuration come from https://mailman.stanford.edu/pipermail/mininet-discuss/2015-October/006525.html
        hosts = [self.addHost('h%d' % i, ip='192.168.100.%d' % i, mac='00:00:00:00:00:0%d' % i) for i in range(1, count + 1)]
        switches = [self.addSwitch('s%d' % i) for i in range(1, count + 1)]
        for i in range(count):
            self.addLink(hosts[i], switches[i])
        for i in range(count-1):
            # loss gets worse the further along the chain you go
            self.addLink(switches[i], switches[i+1], loss=(i*20))

# Each host is connected to its own switch
# The switches are connected in a diamond. There is a left corner, bottom corner, and right
# corner. The top_count arg determines how many switch/host pairs are in the top path.
# modified from https://github.com/mininet/mininet/wiki/Introduction-to-Mininet
class DiamondTopo(Topo):
    def build(self, top_count=1):
        # as configured, can currently only handle up to 9 hosts due to the way mac is formatted
        # the ip and mac configuration come from https://mailman.stanford.edu/pipermail/mininet-discuss/2015-October/006525.html
        
        # make the bottom path first
        bottom_count = 3
        bottom_hosts = [self.addHost('h%d' % i, ip='192.168.100.%d' % i, mac='00:00:00:00:00:0%d' % i) for i in range(1, bottom_count + 1)]
        bottom_switches = [self.addSwitch('s%d' % i) for i in range(1, bottom_count + 1)]
        for i in range(bottom_count):
            self.addLink(bottom_hosts[i], bottom_switches[i])
        for i in range(bottom_count-1):
            self.addLink(bottom_switches[i], bottom_switches[i+1])

        # make the top path
        top_hosts = [self.addHost('h%d' % i, ip='192.168.100.%d' % i, mac='00:00:00:00:00:0%d' % i) for i in range(bottom_count + 1, bottom_count + top_count + 1)]
        top_switches = [self.addSwitch('s%d' % i) for i in range(bottom_count + 1, bottom_count + top_count + 1)]
        for i in range(top_count):
            self.addLink(top_hosts[i], top_switches[i])
        for i in range(top_count-1):
            self.addLink(top_switches[i], top_switches[i+1])

        # link the top and bottom paths together
        self.addLink(bottom_switches[0], top_switches[0])
        self.addLink(bottom_switches[-1], top_switches[-1])

topos = {
    'chain': (lambda: ChainTopo()),
    'diamond': (lambda: DiamondTopo())
}


if __name__ == '__main__':
    net = Mininet(topo=ChainTopo(3), controller=RemoteController, link=TCLink, build=False)
    net.build()
    net.start()
    #net.startTerms()
    for h in net.hosts:
        h.cmd('arp -s 192.168.1.253 FF:FF:FF:FF:FF:FD') # so hosts can self-announce to their switch
        h.cmd('python ./mininet-host-program.py &')
    net['h1'].cmd('arp -s 192.168.255.1 AB:CD:EF:AB:CD:EF') # so h1 can send to "internet"
    CLI(net)
    net.stop()