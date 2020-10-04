#!/usr/bin

import os
import random
from sys import *
import socket
import struct
from scapy.layers.inet import ICMP
from scapy.layers.inet import  IP
from scapy.sendrecv import sr1

class Traceroute(object):

    def __init__(self, host_name):
        self.host_name = host_name

    def udp_troute(self):

            host_address = socket.gethostbyname(self.host_name)
            host_name = self.host_name
            max_hops = 30
            port = random.choice(range(33434, 33535))
            ttl = 1
            while True:
                reciever_sock = self.make_reciever_sock()
                sender_sock= self.make_sender_sock(ttl)

                reciever_sock.bind(("", port))
                print(ttl, end=' ')
                sender_sock.sendto(bytes("", "utf-8"), (host_name, port))

                router_addr = None
                router_name = None
                done = False
                number_of_try = 3
                while not done and number_of_try > 0:
                    try:
                        # sender_sock.settimeout(3)
                        data, router_addr = reciever_sock.recvfrom(512)
                        done = True
                        router_addr = router_addr[0]
                        try:
                            router_name = socket.gethostbyaddr(router_addr)[0]
                        except socket.error:
                            router_name = router_addr
                    except socket.error:
                        number_of_try = number_of_try - 1
                        print("* ", end= ' ')

                sender_sock.close()
                reciever_sock.close()

                if not done:
                    pass

                if router_addr is not None:
                    curr_host = "%s (%s)" % (router_name, router_addr)
                else:
                    curr_host = ""

                print(curr_host)

                ttl += 1
                if router_addr == host_address or ttl > max_hops:
                    break
    def make_reciever_sock(self):
            reciever_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            timeval = struct.pack("LL", 3, 0)  # converting network binary version
            reciever_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeval) #(level, optname, value)
            return reciever_sock
    def make_sender_sock(self, ttl):
        sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sender_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)  # set the (level, option, time to live)
        return sender_sock

    def icmp_troute(self):
        ttl = 1
        done = False
        mac_hopes = 30
        while not done and ttl <= mac_hopes:

            for tries in range(1, 4):
                p = sr1(IP(dst=self.host_name, ttl=ttl) / ICMP(id=os.getpid()),
                    verbose=0)
                # if time exceeded due to TTL exceeded
                if p[ICMP].type == 11 and p[ICMP].code == 0:
                    print (ttl, p.src)
                    ttl += 1
                    break

                elif p[ICMP].type == 3 and tries == 3:
                    print('* * *')
                    ttl = ttl + 1
                    break

                elif p[ICMP].type == 0:
                    print(ttl, p.src)
                    ttl = ttl + 1
                    done = True


def main(ip_address):

    #ip_address = input("Please")

    troute = Traceroute(ip_address)

    usr_selection = (int)(input("Please select one of the following tracerouting methods:"
                                "\n 1. UDP"
                                "\n 2. ICMP\n"))

    if(usr_selection == 1):
        print("you have entered 1")
        try:
            print('Traceroute started')
            troute.udp_troute()

        except KeyboardInterrupt:
            print("intrupted")

    elif(usr_selection == 2):
        print("you have entered 2")
        try:
            print('Traceroute started')
            troute.icmp_troute()
        except KeyboardInterrupt:
            print("intrupted")

    else:
        print("Please enter the right number")
        main(ip_address)

if __name__ == '__main__':
    main(argv[1])
