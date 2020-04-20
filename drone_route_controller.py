# Copyright 2012-2013 James McCauley
# Modified extensively by Jake Luoma for CSCI 5273 Network Systems at CU Boulder Spring 2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
A drone swarm learning switch

For each switch:
1) Keep a table that maps DPID to connection, connected host, and routing tables.
   Stock this table using info from hello messages, routing broadcasts, and IP packets.
   Routing tables map IP addresses to information about that IP address
   including IP, mac, port, etx, and whether it has access to internet.
2) Keep a list of host IP addresses with internet access.
3) When you see a packet destined for an address outside the swarm
   (192.168.100.xxx is reserved for the swarm), try to forward it to a host
   with internet access so it can be forwarded appropriately.
4) If you don't have a route to the destination IP address, store the packet in
   a temporary buffer. Try to send the packets in the buffer occasionally.
5) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.

Note that each host is mapped 1:1 with a switch. They are considered a connected
pair. Switches are connected to each other and forward packets. The switches/controller
are responsible for generating routing information.

Routing tables are shared every 3 seconds. They are flooded out all ports 
NUM_HELLO_TRANSMISSIONS times to generate ETX information.
During that three seconds, a switch collects all routing tables received. After the
3 seconds are over, it consolidates all routing tables received, culls them so only
the best paths to each known IP address are left, and updates its routing table. This
means that if a route to an IP address during that 3 seconds of collection is not found and
it's in a currently existing table, it is removed. This ensures that the network adapts
in the case of a broken link.
"""

from pox.core import core
import pox
log = core.getLogger()

import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.udp import udp
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
import pox.misc

import pox.openflow.libopenflow_01 as of

from pox.lib.revent import *

import json
import time

# Timeout for flows
FLOW_IDLE_TIMEOUT = 3

# Maximum number of packets to buffer on a switch for an unknown IP
MAX_BUFFERED_PER_IP = 5

# Maximum time to hang on to a buffer for an unknown IP in seconds
MAX_BUFFER_TIME = 12

# Number of hello transmissions
NUM_HELLO_TRANSMISSIONS = 5

class DPID_Entry (object):
  def __init__ (self, connection, connected_host, route_table1, route_table2):
    self.connection = connection
    self.connected_host = connected_host
    self.route_table1 = route_table1
    self.route_table2 = route_table2

class Host_Entry (object):
  def __init__ (self, ip, mac, port, received_etx, internet):
    self.ip = ip
    self.mac = mac
    self.port = port
    self.received_etx = received_etx
    self.internet = internet
    self.received_count = 1
    self.etx = received_etx

def diff(li1, li2):
  li_dif = [i for i in li1 if i not in li2]
  return li_dif

class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False):
    # These are "fake gateways" -- we'll answer ARPs for them with MAC
    # of the switch they're connected to.
    self.fakeways = set(fakeways)

    # If this is true and we see a packet for an unknown
    # host, we'll ARP for it.
    self.arp_for_unknowns = arp_for_unknowns

    # (dpid,IP) -> [(expire_time,buffer_id,in_port), ...]
    # These are buffers we've gotten at this datapath for this IP which
    # we can't deliver because we don't know where they go.
    self.lost_buffers = {}

    # For each switch, we capture the IP address, MAC address,
    # relevant switch port, and connection for the attached host
    self.dpid_table = {}

    # A global list of host IP addresses with internet access
    self.hosts_with_internet = []

    # This timer handles expiring stuff
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)

    # This timer handles propagation of routing info
    self._routing_timer = Timer(3, self._routing_propagation, recurring=True)

    self.listenTo(core)

  def _handle_expiration (self):
    # Called by a timer so that we can remove old items.
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k

      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          # This packet is old.  Tell this switch to drop it.
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)

    # Remove empty buffer bins
    for k in empty:
      del self.lost_buffers[k]

  # Called by a timer so that we can prompt switches to share
  # their routing information
  def _routing_propagation(self):
    for dpid in self.dpid_table.keys():
      connected_host = self.dpid_table[dpid].connected_host
      table1 = self.dpid_table[dpid].route_table1
      table2 = self.dpid_table[dpid].route_table2
      
      # cull route_table 2 lists into just one entry with best etx
      for ip in table2.keys():
        ele = table2[ip][0] # there's always at least one entry for an IP
        for e in table2[ip]:
          if e.ip == connected_host.ip:
            continue
          e.etx += NUM_HELLO_TRANSMISSIONS / e.received_count
          if e.etx < ele.etx:
            ele = e
        table2[ip] = ele      

      # make routing table 1 = routing table 2
      self.dpid_table[dpid].route_table1 = self.dpid_table[dpid].route_table2
      e = [self.dpid_table[dpid].connected_host]
      self.dpid_table[dpid].route_table2 = {self.dpid_table[dpid].connected_host.ip : e}

    # send the new routing table to the connected host
    for dpid in self.dpid_table.keys():
      # construct payload of IP to mac pairs as a json string
      # ie. '{"192.168.1.200" : "AA:AA:AA:AA:AA:AF", "..."}'
      payload = '{'
      for ip in self.dpid_table[dpid].route_table1.keys():
        # if it's the host IP, ARP will crash, so skip it
        if ip == self.dpid_table[dpid].connected_host.ip:
          continue
        mac = self.dpid_table[dpid].route_table1[ip].mac
        pair = '"%s" : "%s", ' % (ip.toStr(), mac.toStr())
        payload = payload + pair
      # to catch the case where only the host address is known
      if len(payload) > 1:
        payload = payload[:-2]
      payload = payload + '}'

      # pox-dev.noxrepo.narkive.com/H9Ef9T3S/errors-when-sending-new-created-packets
      udp_packet = udp()
      udp_packet.srcport = 10000
      udp_packet.dstport = 10001
      udp_packet.payload = payload
      udp_packet.len = udp.MIN_LEN + len(payload)
      udp_packet.set_payload(payload)

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + udp_packet.len
      ipv4_packet.protocol = ipv4.UDP_PROTOCOL
      ipv4_packet.dstip = self.dpid_table[dpid].connected_host.ip
      ipv4_packet.srcip = IPAddr('192.168.1.254')
      ipv4_packet.set_payload(udp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      eth_packet.dst = self.dpid_table[dpid].connected_host.mac
      eth_packet.src = EthAddr('FF:FF:FF:FF:FF:FE')
      eth_packet.type = ethernet.IP_TYPE

      msg = of.ofp_packet_out(data=eth_packet)
      msg.actions.append(of.ofp_action_output(port=self.dpid_table[dpid].connected_host.port))
      self.dpid_table[dpid].connection.send(msg)

    # flood the new routing table to any connected switches
    for dpid in self.dpid_table.keys():
      # construct payload of ip, mac, etx, internet tuples as json list of dicts
      # ie. '[{"ip" : "192.168.1.200", "mac": "AA:AA:AA:AA:AA:AF", "etx" : "1", "internet" : "no"}, {...}]'
      payload = '['
      ports = ""
      for ip in self.dpid_table[dpid].route_table1.keys():
        mac = self.dpid_table[dpid].route_table1[ip].mac
        etx = self.dpid_table[dpid].route_table1[ip].etx
        internet = self.dpid_table[dpid].route_table1[ip].internet
        entity = '{"ip" : "%s", "mac" : "%s", "etx" : "%f", "internet" : "%s"}, ' % (ip.toStr(), mac.toStr(), etx, internet)
        payload = payload + entity

        port = self.dpid_table[dpid].route_table1[ip].port
        ports += str(port) + " "
      payload = payload[:-2]
      payload = payload + ']'
      payload = payload.encode('utf-8', 'ignore')

      log.debug("%s flooding routing message: %s" % (dpid, payload))
      log.debug("%s" % ports)

      udp_packet = udp()
      udp_packet.srcport = 10002
      udp_packet.dstport = 10003
      udp_packet.payload = payload
      udp_packet.len = udp.MIN_LEN + len(payload)
      udp_packet.set_payload(payload)

      ipv4_packet = ipv4()
      ipv4_packet.iplen = ipv4.MIN_LEN + udp_packet.len
      ipv4_packet.protocol = ipv4.UDP_PROTOCOL
      ipv4_packet.dstip = IPAddr('192.168.1.254')
      ipv4_packet.srcip = IPAddr('192.168.1.255')
      ipv4_packet.set_payload(udp_packet)

      eth_packet = ethernet()
      eth_packet.set_payload(ipv4_packet)
      eth_packet.dst = EthAddr('FF:FF:FF:FF:FF:FE')
      eth_packet.src = EthAddr('FF:FF:FF:FF:FF:FC')
      eth_packet.type = ethernet.IP_TYPE

      msg = of.ofp_packet_out(data=eth_packet)
      msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))

      for _ in range(NUM_HELLO_TRANSMISSIONS):
        self.dpid_table[dpid].connection.send(msg)

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    """
    We may have "lost" buffers -- packets we got but didn't know
    where to send at the time.  We may know now.  Try and see.
    """
    if (dpid,ipaddr) in self.lost_buffers:
      # Yup!
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport,
                packet.next.srcip,packet.next.dstip)

      # Send any waiting packets...
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      # Handle if it's a host hello message
      dstaddr = packet.next.dstip
      if dstaddr == "192.168.1.253":
        log.debug("got hello message from %s" % packet.next.srcip)
        if packet.next.srcip == "192.168.100.3":
          host_entry = Host_Entry(packet.next.srcip, packet.src, inport, 1.0, "yes")
          self.hosts_with_internet.append(packet.next.srcip)
          log.debug("%s has internet access" % packet.next.srcip)
        else:
          host_entry = Host_Entry(packet.next.srcip, packet.src, inport, 1.0, "no")
        host_entry.received_count = NUM_HELLO_TRANSMISSIONS
        route_table1 = {packet.next.srcip : host_entry}
        route_table2 = {packet.next.srcip : [host_entry]}
        self.dpid_table[dpid] = \
                    DPID_Entry(event.connection, host_entry, route_table1, route_table2)
                
        # push rule for sharing routing info (push received packet to controller to handle)
        msg = of.ofp_flow_mod()
        msg.match._dl_type = 0x800 # match on IP
        msg.match._nw_proto = 17 # this is for UDP
        msg.match._tp_src = 10002
        msg.match._tp_dst = 10003
        msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
        event.connection.send(msg)

      # Handle if it's a routing info packet
      elif dstaddr == "192.168.1.254":  # works, but should modify match since flow rule is on ports
        payload = packet.payload.payload.payload
        routes = json.loads(payload.decode("utf-8"))
        for route in routes:
          ip = IPAddr(route["ip"])
          mac = EthAddr(route["mac"])
          received_etx = float(route["etx"])
          internet = route["internet"]

          # update relevant dpid's table
          table = self.dpid_table[dpid].route_table2.get(ip, None)
          if table is None:
            table = [Host_Entry(ip, mac, inport, received_etx, internet)]
            self.dpid_table[dpid].route_table2[ip] = table
          else:
            already_present_on_port = False
            for entry in table:
              if entry.port == inport:
                already_present_on_port = True
                entry.received_count += 1
                break
            if already_present_on_port == False:
              self.dpid_table[dpid].route_table2[ip].append(Host_Entry(ip, mac, inport, received_etx, internet))
        
      # handle if it's destined for the internet
      # note: the swarm's address space is defined to only be within 192.168.100.xxx
      elif dstaddr.toStr()[:11] != "192.168.100": # must be destined for outside the swarm. Forward to the internet!
          log.debug("%s Got a packet destined for the internet!" % dpid)
          
          # if the switch/host handling this has internet access,
          # "forward" to the internet by writing the contents to log
          if self.dpid_table[dpid].connected_host.internet == "yes":
            log.debug('%s "Sending" packet to internet' % dpid)

          else: # forward in the direction of the nearest host with internet access
            if len(self.hosts_with_internet) == 0: # no known hosts with internet
              log.debug("No known hosts with internet access")
              # Add to tracked buffers
              if (dpid,dstaddr) not in self.lost_buffers:
                self.lost_buffers[(dpid,dstaddr)] = []
              bucket = self.lost_buffers[(dpid,dstaddr)]
              entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
              bucket.append(entry)
              while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

            # there's at least one host with internet. send to the one with lowest etx.  
            closest_ip = self.hosts_with_internet[0]
            closest_etx = self.dpid_table[dpid].route_table1[closest_ip].etx
            for host_ip in self.hosts_with_internet:
              etx = self.dpid_table[dpid].route_table1[host_ip].etx
              if etx < closest_etx:
                closest_etx = etx
                closest_ip = host_ip

            log.debug("%s forwarding packet directed to internet!" % dpid)
            # now send the packet
            prt = self.dpid_table[dpid].route_table1[closest_ip].port
            msg = of.ofp_packet_out(data=packet, action=of.ofp_action_output(port=prt))
            event.connection.send(msg)

      # Try to forward
      elif dstaddr in self.dpid_table[dpid].route_table1.keys():
        # We have info about what port to send it out on...

        prt = self.dpid_table[dpid].route_table1[dstaddr].port
        mac = self.dpid_table[dpid].route_table1[dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the " +
                      "input port" % (dpid, inport, dstaddr))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          match = of.ofp_match.from_packet(packet, inport)
          match.dl_src = None # Wildcard source MAC

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=of.ofp_match.from_packet(packet,
                                                               inport))
          event.connection.send(msg.pack())

          # now send the packet
          msg = of.ofp_packet_out(data=packet, action=of.ofp_action_output(port=prt))
          event.connection.send(msg)
      else:
        # We don't know this destination.
        # We track this packet so that we can try to resend it later
        # if we learn the destination.

        # Add to tracked buffers
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]


def launch (fakeways="", arp_for_unknowns=None):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns)