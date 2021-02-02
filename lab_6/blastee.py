#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time
def init(filepath):
    f = open(filepath,'r')
    line = f.readline()
    mode_b,blaster_ip,mode_n,num = line.strip().split(' ')
    f.close()
    return blaster_ip,int(num)
def mk_ACK(pkt,dst_mac,src_mac,dst_ip,src_ip):
    eth = Ethernet()
    eth.dst = dst_mac
    eth.src = src_mac
    
    ip = IPv4(protocol=IPProtocol.UDP)
    ip.dst = dst_ip
    ip.src = src_ip
    
    udp = UDP()  # not use port
    
    bs = pkt[3].to_bytes()
    sequence_num = bs[:4]

    log_info('ack to: {}'.format(int(sequence_num)))
    con = RawPacketContents(sequence_num)  
    payload = RawPacketContents(bs[6:14])
    

    print(len(bs),len(sequence_num))
    return eth + ip + udp + con + payload
    
    
def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    myips = [intf.ipaddr for intf in my_interfaces]
    #myitfs = [intf.name for intf in my_interfaces]
    blaster_ip,num = init("blastee_params.txt")
    middlebox_mac = '40:00:00:00:00:02'
    print(mymacs)
    print(myips)
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
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))
            
            
            ack = mk_ACK(pkt,middlebox_mac,mymacs[0],blaster_ip,myips[0])            
            #log_info("ack:{}".format(ack))
            net.send_packet('blastee-eth0',ack)
            

    net.shutdown()
