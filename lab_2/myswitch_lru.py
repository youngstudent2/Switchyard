#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
from collections import OrderedDict

class mac2port_table_lru(OrderedDict):
    def __init__(self,capacity):
        self.capacity = capacity
        self.table = OrderedDict()

    def get(self,key):
        if key in self.table: #get and update
            value = self.table.pop(key)
            self.table[key] = value
        else:
            value = None
        return value
    
    def set(self,key,value):
        if key in self.table: 
            value = self.table.pop(key)
            self.table[key] = value
        else:
            if len(self.table) == self.capacity:
                d_value = self.table.popitem(last = False)
                log_info(self.table)
                log_info('#######to delete : {}#######'.format(d_value))
                self.table[key] = value
            else:
                self.table[key] = value

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mac2port_table = mac2port_table_lru(5)
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        
        #check port
        log_info ("In {} received packet {} on {}".format(net.name, packet, input_port))

        mac2port_table.set(packet[0].src,input_port)

        output_port = mac2port_table.get(packet[0].dst)

        log_info("{} output_port:{}".format(packet[0].dst,output_port))

        if packet[0].dst in mymacs:
            log_info ("Packet intended for me")
        elif output_port!=None:
            log_info("send packet to {} by port {}".format(packet[0].dst, output_port))
            net.send_packet(output_port, packet)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
