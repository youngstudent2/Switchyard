#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time
def init_drop_rate(filepath):
    f = open(filepath,"r")
    line = f.readline()
    mode, param = line.strip().split(' ')
    print("drop rate:{}".format(param))
    f.close()
    return float(param)
def is_lucky_packet(drop_rate):
    ran = random.random()
    if ran > drop_rate:
        return True
    else:
        return False
def modify_packet_header(packet,sourceMAC,nextMAC):
    
    eth = packet.get_header(Ethernet)
    
    eth.dst = nextMAC
    eth.src = sourceMAC
    
            
def switchy_main(net):
    blaster_mac = '10:00:00:00:00:01'
    blastee_mac = '20:00:00:00:00:01'
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    drop_rate = init_drop_rate("middlebox_params.txt")
    total_drop = 0
    blaster_count = 0 
    blastee_count = 0
    while True:
        gotpkt = True
        try:
            timestamp,dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''
            if is_lucky_packet(drop_rate):
                modify_packet_header(pkt,mymacs[1],blastee_mac)
                net.send_packet("middlebox-eth1", pkt)
            else: # drop it
                log_debug("drop it!")
                total_drop += 1
                log_info("drop packet (ER --> EE) : {} total drop : {}".format(int(pkt[3].to_bytes()[:32]),total_drop))
            
            blaster_count += 1
            
            
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            if is_lucky_packet(drop_rate):
                modify_packet_header(pkt,mymacs[0],blaster_mac)
                net.send_packet("middlebox-eth0", pkt)
                
            else: # drop it
                log_debug("drop it!")
                total_drop += 1
                log_info("drop packet (EE --> ER) : {} total drop : {}".format(int(pkt[3].to_bytes()[:32]),total_drop))
            blastee_count += 1
        else:
            log_debug("Oops :))")
        log_info("blaster:{} blastee:{}".format(blaster_count,blastee_count))
    net.shutdown()
