#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time

def init(filepath):
    f = open(filepath,'r')
    line = f.readline()
    print('init params:{}'.format(line))
    mode_b,blastee_ip, \
        mode_n,num, \
            mode_l,length, \
                mode_w,window, \
                    mode_t,timeout, \
                        mode_r,recv_timeout = line.strip().split(' ')
    f.close()
    return blastee_ip,int(num),int(length),int(window),float(timeout)/1000.0,float(recv_timeout)/1000.0

def mk_pkt(sequence_num,dst_mac,src_mac,dst_ip,src_ip,payload_length):
    p = Ethernet() + IPv4(protocol=IPProtocol.UDP) + UDP()
    
    p[0].dst = dst_mac
    p[0].src = src_mac
    p[1].dst = dst_ip
    p[1].src = src_ip
    seq = str(sequence_num)    
    length = str(payload_length)
    p += RawPacketContents(seq.to_bytes(4)+length.to_bytes(2))
 
    payload = '0'.ljust(payload_length/8) 
    p += RawPacketContents(payload)
    
    return p

class Sender_Window():
    def __init__(self,size,timeout,num,length):
        self.rhs = -1
        self.lhs = 0
        self.size = size
        self.length = length
        self.window = []
        self.timeout = timeout
        self.num = num
    def start(self):
        self.startTime = time.time()
        self.reNum = 0
        self.toNum = 0
        self.packet_count = 0
        self.update_time = self.startTime
    def end(self):
        self.endTime = time.time()
        total_time = self.endTime - self.startTime    
        total_through_bytes = self.length*self.packet_count
        total_good_bytes = self.length*(self.packet_count-self.reNum)
        throughput = total_through_bytes / total_time
        goodput = total_good_bytes / total_time
        print("transmission statistics:\ntotal TX time:{}\nNumber of reTX:{}\nNumber of coarse TOs:{}\nThroughput:{}\ngoodput:{}\nall:{}\n" \
            .format(total_time,self.reNum,self.toNum,throughput,goodput,self.packet_count))
        
    def dealACK(self,ack):
        seq = ack[3].to_bytes()[:31]
        sequence_num = int(seq)
        self.window[sequence_num]['state'] = 2 # ack 
        log_info("ack {}".format(sequence_num))

    def load_packet(self,packet):
        self.rhs += 1
        self.window.append({
            'packet':packet,
            'state':0 # to send
        })
        return self.rhs   
         
    def send_packet(self,net,index):
        if index >= self.lhs and index <= self.rhs:
            net.send_packet('blaster-eth0',self.window[index]['packet'])
            self.window[index]['state'] = 1
            self.packet_count += 1
       
        
        
    def need_load(self):
        if self.rhs >= self.num - 1: # no packet need to send
            return False
        if self.rhs - self.lhs + 1 >= self.size:
            return False
        
        return True
         
        
    def check_timeout(self):
        now = time.time()
        
        if now - self.update_time > self.timeout:
            self.toNum += 1
        
        else:
            return -1

        for i in range(self.rhs-self.lhs+1):
            item = self.window[self.lhs + i]
            if item['state'] == 1:
                self.reNum += 1
                print('renum:',self.reNum)
                # timeout , resend it
                return self.lhs + i
            
        return -1
    
    def update_window(self):
        if self.lhs == self.rhs and self.rhs == self.num - 1:
            return 0  # done !

        if self.rhs>=self.lhs and self.window[self.lhs]['state'] == 2:
            self.lhs += 1
            while self.lhs<self.rhs and self.window[self.lhs]['state'] == 2 :
                self.lhs += 1      
            self.update_time = time.time()  

        return 1

    
        
        
        

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    blastee_ip,num,length,window_size,timeout,recv_timeout = init('blaster_params.txt')
    print(blastee_ip,num,length,window_size,timeout,recv_timeout)
    middlebox_mac = "40:00:00:00:00:01"
    sw = Sender_Window(window_size,timeout,num,length)
    sw.start()
    log_info("start")
    seq = 0
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            timestamp,dev,pkt = net.recv_packet(timeout=recv_timeout)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_info("I got a packet")
            sw.dealACK(pkt)
        else:
            #log_info("Didn't receive anything")
        
            if sw.need_load():
                index = sw.load_packet(mk_pkt(seq,middlebox_mac,mymacs[0],blastee_ip,myips[0],length))
                log_info("new packet with seq {} send".format(seq))
                seq += 1                
                sw.send_packet(net,index)
            else:                
                index = sw.check_timeout()   
                if index > -1:
                    log_info("check timeout and resend packet {}".format(index))
                sw.send_packet(net,index) 
              
        ret = sw.update_window()
        if ret == 0:
            log_info('done!')
            sw.end()
            break
            
        

            
    net.shutdown()
