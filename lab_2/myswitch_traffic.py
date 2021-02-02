#!/usr/bin/env python3
'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *


class LFUNode():
    def __init__(self, key, value):
        self.freq = 0
        self.key = key
        self.value = value
    def __str__(self):
        return "{} {} {}".format(self.key,self.value,self.freq)

class mac2port_table_traffic():
    def __init__(self,capacity):
        self.capacity = capacity
        self.map = {}
        self.freq_map = {}

    def get(self,key):
        if key in self.map: #get and update
            node = self.map.get(key)
            freq = node.freq
            self.freq_map[freq].remove(node)
            if len(self.freq_map[freq]) == 0:
                del self.freq_map[freq]

            freq += 1
            print(node)
            node.freq = freq
            if freq not in self.freq_map:
                self.freq_map[freq] = []
            self.freq_map[freq].append(node)
            
        else:
            return None
        return node.value
    
    def set(self,key,value):
        
        if key in self.map:
            node = self.map.get(key)
            node.value = value
            
        else:
            if len(self.map) == self.capacity:
                min_freq = min(self.freq_map)
                node = self.freq_map[min_freq].pop()
                del self.map[node.key]
            node = LFUNode(key,value)
            node.freq = 0
            self.map[key] = node
            if node.freq not in self.freq_map:
                self.freq_map[node.freq] = []
            self.freq_map[node.freq].append(node)
              
    def print(self):
        print("\nmy table({}) is :".format(len(self.map)))
        for key,value in self.freq_map.items():
            for v in value:
                print("MAC:{} port:{} freq:{}".format(v.key,v.value,v.freq))   
        print("")         

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    mac2port_table = mac2port_table_traffic(5)
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
  
        mac2port_table.print()

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

