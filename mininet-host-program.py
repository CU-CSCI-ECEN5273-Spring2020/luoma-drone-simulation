import socket

UDP_IP = "192.168.1.253"
UDP_PORT = 10000
MESSAGE = "Host announcement"

sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
sock.sendto(MESSAGE, (UDP_IP, UDP_PORT))
