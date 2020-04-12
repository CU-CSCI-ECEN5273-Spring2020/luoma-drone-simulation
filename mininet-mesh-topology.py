#!/usr/bin/python

from mininet.cli import CLI
from mininet.node import Controller, OVSSwitch
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


"""
########
Controllers
########
"""
# A simple script to start my custom POX controller
# TODO change name to custom script
class POXBridge(Controller):
    def start(self):
        self.pox = '%s/pox/pox.py' % os.environ['HOME']
        self.cmd(self.pox, 'forwarding.l2_learning &')

    def stop( self ):
        self.cmd('kill %' + self.pox)
                                                                                                       
controllers = {'poxbridge': POXBridge}


"""
########
Switches
########
"""
# modified from https://github.com/mininet/mininet/blob/master/examples/controllers.py
# Code to enable each switch having its own controller
defaultControllerPort = 6633
numSwitches = 3
controllers = [POXBridge('c%d' % i, port=defaultControllerPort + i) for i in range(0, numSwitches)]
cmap = {}
for i in range(0, numSwitches):
    cmap['s%d' % i+1] = controllers[i]

class MultiSwitch(OVSSwitch):
    def start(self, controllers):
        return OVSSwitch.start(self, [cmap[self.name]])

switches = {'multiswitch' : MultiSwitch}


if __name__ == '__main__':
    net = Mininet(topo=ChainTopo(3), switch=MultiSwitch, build=False)
    for c in controllers:
        net.addController(c)
    net.build()
    net.start()
    CLI(net)
    net.stop()