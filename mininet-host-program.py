import json
import socket
import subprocess

def inform_switch_of_self():
    UDP_IP = "192.168.1.253"
    UDP_PORT = 10000
    MESSAGE = "Host announcement"

    sock = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP
    sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))

def listen_for_routing_updates():
    HOST = '' # symbolic name meaning all available interfaces
    UDP_PORT = 10001

    sock = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP

    sock.bind((HOST, UDP_PORT))

    while True:
        message, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        #print "received message: ", message
        ip_to_mac_dict = json.loads(message)
        # subprocess.call(['ip', '-s', '-s', 'neigh', 'flush', 'all']) # flush the arp cache
        for ip, mac in ip_to_mac_dict.iteritems(): # populate the arp cache with reachable hosts
            subprocess.call(['arp', '-s', str(ip), str(mac)])

if __name__ == '__main__':
    inform_switch_of_self()
    listen_for_routing_updates()