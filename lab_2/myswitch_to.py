#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
class mac2port_table_item:
    timestamp = 0
    port = ""
    def __init__(self,timestamp,port):
        self.timestamp = timestamp
        self.port = port
    def __repr__(self):
        return "<mac2port table item>time=%d,port=%s"%(self.timestamp,self.port)

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mac2port_table = {}
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        nowTime = int(time.time())
        
        #check port
        log_info ("In {} received packet {} on {}".format(net.name, packet, input_port))
        #learning
        mac2port_table[packet[0].src] = mac2port_table_item(nowTime,input_port)

        #get output port and judge port timeout
        output_port_item = mac2port_table.get(packet[0].dst,mac2port_table_item(0,""))
        
        if output_port_item.timestamp and nowTime-output_port_item.timestamp>10: # 10s timeout
            del mac2port_table[packet[0].dst]
            output_port_item = mac2port_table_item(0,"")

        log_info("table:{}".format(mac2port_table))
        log_info("{} output_port_item:{}".format(packet[0].dst,output_port_item))
        if packet[0].dst in mymacs:
            log_info ("Packet intended for me")
        elif output_port_item.timestamp:
            log_info("send packet to {} by port {}".format(packet[0].dst, output_port_item.port))
            net.send_packet(output_port_item.port, packet)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()
