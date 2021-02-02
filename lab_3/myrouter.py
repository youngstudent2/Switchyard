#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class ip2mac_table_item():
    def __init__(self,mac):
        self.time = time.time()
        self.value = mac
    def timeout(self):
        return time.time()-self.time > 10
    def __str__(self):
        return "mac:{} time:{}".format(self.value,self.time)
class ip2mac_table():
    def __init__(self):
        self.table = {}

    def get(self,key):
        if key in self.table: #get and update
            value = self.table[key]
            if value.timeout():
                log_info("Timeout Item:{}".format(value))
                value = None
                self.table.pop(key)
            else:
                value = value.value
        else:
            value = None
        return value
    
    def set(self,key,value):
        self.table[key] = ip2mac_table_item(value)


    def print(self):
        now = time.time()
        print('')
        print("here is table:")
        for key,value in self.table.items():
            print("ip:{} mac:{} time:{}".format(key,value.value,now - value.time))
        print('')
        
class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.table = ip2mac_table()

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        print("interfaces:")
        for i in self.net.interfaces():
            print("{}->{}".format(i.ethaddr,i.ipaddr))

        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_info("Got a packet: {} on {}".format(str(pkt),dev))
                arp = pkt.get_header(Arp)
                log_info("arp header: {}".format(arp))
                
                if arp is None:
                    continue
                else:          
                    try:    
                        interface = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                    except KeyError:
                        interface = None
                    
                    log_info("my interface: {}".format(interface))
                    if interface is not None:   #arp is for me
                        reply = create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                        log_info("reply arp packet: {} by port {}".format(reply, dev))
                        self.net.send_packet(dev, reply)
                    else:   #arp is not for me , but i will remember it                       
                        if arp.targethwaddr != "00:00:00:00:00:00": #mac has been assigned(reply arp packet) 
                            self.table.set(arp.targetprotoaddr,arp.targethwaddr)
                        else:
                            target = self.table.get(arp.targetprotoaddr)
                            if target is not None:
                                log_info("{} is in my table -> {}".format(arp.targetprotoaddr,target))

                    # add sender's addr
                    self.table.set(arp.senderprotoaddr,arp.senderhwaddr)
                    self.table.print()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
