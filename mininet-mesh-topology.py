#!/usr/bin/python

from mininet.cli import CLI
from mininet.node import RemoteController, OVSSwitch
from mininet.net import Mininet
from mininet.topo import Topo

import os

"""
########
Topologies
########
"""
# Each host is connected to its own switch
# The switches are connected in a chain
# modified from https://github.com/mininet/mininet/wiki/Introduction-to-Mininet
class ChainTopo(Topo):
    def build(self, count=3):
        # numSwitches used by Switches functions to enable each switch
        # to have its own controller
        global numSwitches
        numSwitches = count

        # as configured, can currently only handle up to 9 hosts due to the way mac is formatted
        # the ip and mac configuration come from https://mailman.stanford.edu/pipermail/mininet-discuss/2015-October/006525.html
        hosts = [self.addHost('h%d' % i, ip='192.168.100.%d' % i, mac='00:00:00:00:00:0%d' % i) for i in range(1, count + 1)]
        switches = [self.addSwitch('s%d' % i) for i in range(1, count + 1)]
        for i in range(count):
            self.addLink(hosts[i], switches[i])
        for i in range(count-1):
            self.addLink(switches[i], switches[i+1])

topos = {'chain': (lambda: ChainTopo())}


if __name__ == '__main__':
    net = Mininet(topo=ChainTopo(3), controller=RemoteController, build=False)
    net.build()
    net.start()
    #net.startTerms()
    for h in net.hosts:
        h.cmd('arp -s 192.168.1.253 FF:FF:FF:FF:FF:FD')
        h.cmd('python ./mininet-host-program.py &')
    CLI(net)
    net.stop()