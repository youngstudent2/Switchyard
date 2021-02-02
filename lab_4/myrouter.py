#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *
from switchyard.lib.address import *
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
   
class forwarding_item():
    def __init__(self,ip,prefix,next_hop,itf):
        ipaddr = IPv4Address(ip)
        prefixaddr = IPv4Address(prefix)
        ipnum = int(ipaddr)&int(prefixaddr)
        ipnet = str(IPv4Address(ipnum))
        self.prefixnet = IPv4Network(ipnet+'/'+prefix)
        if next_hop is not None:
            self.nexthop = IPv4Address(next_hop)
        else:
            self.nexthop = None
        self.interface = itf
    def match(self,destaddr):
        return destaddr in self.prefixnet
    def prefixlen(self):
        return self.prefixnet.prefixlen
    def __str__(self):
        return "ip:{}    nexthop:{}    interface:{}".format(self.prefixnet.with_netmask,self.nexthop,self.interface)
        
        
class forwarding_table():
    table = []
    def __init__(self,interfaces):
        f = open("forwarding_table.txt","r")
        for line in f:
            ip,prefix,next_hop,itf = line.strip().split(' ')
            self.table.append(forwarding_item(ip,prefix,next_hop,itf))
        f.close()
        for i in interfaces:
            self.table.append(forwarding_item(str(i.ipaddr),str(i.netmask),None,i.name)) 
            #print(i.ipaddr,i.netmask,i.name)
        self.print()
            
    def get(self,destaddr):
        max_prefixlen = -1
        sel = None
        for item in self.table:
            if item.match(destaddr) and item.prefixlen()>max_prefixlen:
                max_prefixlen = item.prefixlen()
                sel = item
        
        return sel
    def print(self):
        for item in self.table:
            print(item)

class ARP_queue():
    q = []
    def __init__(self):
        pass
    
    def add(self,arp,packet,ip,dp,sp):
        self.q.append({'arp':arp,'dest_port':dp,'source_port':sp,'packet':packet,'ip':ip,'time':time.time(),'times':0})
        
    def reply(self,arp,itf,net):
        ip = arp.senderprotoaddr
        mac = arp.senderhwaddr
        for i in range(len(self.q)-1,-1,-1):
            if ip == self.q[i]['ip']:
                # creat eth header
                self.q[i]['packet'][0].dst = mac
                self.q[i]['packet'][0].src = net.interface_by_name(itf).ethaddr
                # send
                net.send_packet(itf,self.q[i]['packet'])
                # pop
                self.q.pop(i) 
    
    def resend(self,net):
        now = time.time()
        for i in range(len(self.q)-1,-1,-1):
            if self.q[i]['times'] >= 4:
                self.q.pop(i)
                continue
            if now - self.q[i]['time'] > 1: # Timeout , resend arp pkt
                net.send_packet(self.q[i]['dest_port'],self.q[i]['arp'])
                self.q[i]['times']+=1
                log_info(self.q[i]['times'])
                
    def print(self):
        for i in self.q:
            print(i)

        
        
        
                      
class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.table = ip2mac_table()        
        self.arpq = ARP_queue() 
        self.interfaces = self.net.interfaces() 
        self.macs = [intf.ethaddr for intf in self.interfaces]
        self.ftable = forwarding_table(self.interfaces)
    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        '''
        print("interfaces:")
        for i in self.net.interfaces():
            print("{}->{}".format(i.ethaddr,i.ipaddr))
        '''
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
                
                if pkt[0].dst in self.macs: # packet is for me
                    log_info("it is for me")
                    #continue
                    
                
                arp = pkt.get_header(Arp)
                log_info("arp header: {}".format(arp))
                
                if arp is not None:          # recv a arp packet
                    try:    
                        interface = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                    except KeyError:
                        interface = None
                    
                    log_info("my interface: {}".format(interface))
                    if interface is not None:   # arp is for me
                        if arp.operation == 1:
                            reply = create_ip_arp_reply(interface.ethaddr,arp.senderhwaddr,arp.targetprotoaddr,arp.senderprotoaddr)
                            log_info("reply arp packet: {} by port {}".format(reply, dev))
                            self.net.send_packet(dev, reply)
                        if arp.operation == 2:
                            res = self.ftable.get(ipv4.dst)                           
                            self.arpq.reply(arp,res.interface,self.net)
                            
                            
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
                
                ipv4 = pkt.get_header(IPv4)
                log_info("ipv4 header:{}".format(ipv4))
                if ipv4 is not None:              # recv a ipv4 packet
                    res = self.ftable.get(ipv4.dst)
                    log_info("search result:{}".format(res))
                    
                    if res is not None:
                        try:    
                            interface = self.net.interface_by_name(res.interface)
                        except KeyError:
                            interface = None


                        ipv4.ttl -= 1
                        if ipv4.ttl <= 0:
                            pass
                        if res.nexthop is not None:
                            next = res.nexthop
                            target = self.table.get(res.nexthop)
                        else:
                            next = ipv4.dst
                            target = self.table.get(ipv4.dst)
                        log_info("target {}".format(target))
                        if target is not None:
                            pkt[0].dst = target
                            pkt[0].src = interface.ethaddr
                            # send
                            self.net.send_packet(res.interface,pkt)
                            log_info("send ipv4 packet directly")
                        else:
                            
                            # send arp and add it into queue to wait for reply
                            arp_request = create_ip_arp_request(interface.ethaddr,interface.ipaddr,next) 
                            self.net.send_packet(res.interface,arp_request)
                            self.arpq.add(arp_request,pkt,next,res.interface,dev)
                            log_info("send arp packet for {}'s ethaddr".format(next))
                    else:
                        pass # not found match ip in forwading table
                    

                    
            # test timeout arp in queue and resend it on source port
            self.arpq.resend(self.net)                
                        
                        
def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
