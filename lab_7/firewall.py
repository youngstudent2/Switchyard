from switchyard.lib.userlib import *
from ipaddress import IPv4Network, IPv4Address
import time
import random
def prefixMatch(netAddr,ipAddr):
    return int(netAddr) & int(ipAddr) == int(netAddr)
def portMatch(rulePort,port):
    if rulePort == -1:
        return 1
    if rulePort == port:
        return 1
    return 0   
def lucky_packet():
    drop_rate = 0.2
    ran = random.random()
    if ran > drop_rate:
        return 1
    else:
        return 0

def permit_method(method):
    if method == 'permit':
        return 1
    elif method == 'deny':
        return -1

class Rule():
    def __init__(self,rule):
        self.method = permit_method(rule[0])
        self.protocol = rule[1]
        if self.protocol == 'ip' or self.protocol == 'icmp':
            if rule[3] == 'any':
                self.src = IPv4Network('0.0.0.0/0')
            else:               
                self.src = IPv4Network(rule[3])
            if rule[5] == 'any':
                self.dst = IPv4Network('0.0.0.0/0')
            else:
                self.dst = IPv4Network(rule[5])
        if self.protocol == 'udp' or self.protocol == 'tcp':
            if rule[3] == 'any':
                self.src = IPv4Network('0.0.0.0/0')
            else:               
                self.src = IPv4Network(rule[3])
            if rule[5] == 'any':
                self.srcport = -1
            else:
                self.srcport = int(rule[5])
            if rule[7] == 'any':
                self.dst = IPv4Network('0.0.0.0/0')
            else:               
                self.dst = IPv4Network(rule[7])
            if rule[9] == 'any':
                self.dstport = -1
            else:
                self.dstport = int(rule[9])
        if rule[-2] == 'ratelimit':
            self.rate = int(rule[-1])
        else: 
            self.rate = -1
        self.token_bucket = TokenBucket(self.rate)
        
        if rule[-1] == 'impair':
            self.impair = 1
        else:
            self.impair = 0
        
    def match(self,pkt):
        
        ip = pkt.get_header(IPv4)
        src = IPv4Address(ip.src)
        dst = IPv4Address(ip.dst)
        pkttype = ip.protocol
        if prefixMatch(self.src.network_address,src) and prefixMatch(self.dst.network_address,dst):
            if self.protocol == 'ip':
                return self.method

            elif self.protocol == 'icmp' and pkttype == IPProtocol.ICMP:
                return self.method

            elif self.protocol == 'tcp' and pkttype == IPProtocol.TCP:                
                tcp = pkt.get_header(TCP)
                if portMatch(self.srcport,tcp.src) and portMatch(self.dstport,tcp.dst):
                    return self.method

            elif self.protocol == 'udp' and pkttype == IPProtocol.UDP:
                udp = pkt.get_header(UDP)
                if portMatch(self.srcport,udp.src) and portMatch(self.dstport,udp.dst):
                    return self.method

        return 0
                 
        
        
    def __str__(self):
        if int(self.src.network_address) == 0:
            src = 'any'
        else:
            src = self.src
        if int(self.dst.network_address) == 0:
            dst = 'any'
        else:
            dst = self.dst
        if self.protocol == 'ip' or self.protocol == 'icmp':
            return "{} {} src {} dst {} impair {} token bucket {}".format(self.method,self.protocol,src,dst,self.impair,self.token_bucket)
        else:
            return "{} {} src {} srcport {} dst {} dstport {} impair {} token bucket {}".format(self.method,self.protocol,src,self.srcport,dst,self.dstport,self.impair,self.token_bucket)
        
            
        
class FireWall():
    rules = []
    def __init__(self):
        pass
    def read_rule(self,filename):
        f = open(filename,'r')
        for line in f:        
            if not line or line[0] == '\n' or line[0] == '#':
                continue
            rule = line.strip().split(' ')
            self.rules.append(Rule(rule))
        
        f.close()    
    def print_rules(self):
        for r in self.rules:
            print(r)
    def impair(self,pkt):
        return not lucky_packet()
    def permit(self,pkt):
        index = 1
        for r in self.rules:
            permit = r.match(pkt)
            if permit == 1:

                if r.token_bucket.permit(pkt):
                    if r.impair and self.impair(pkt):
                        print("impair deny({})".format(index))
                        print(r)
                        return 0
                    return 1
                else:
                    print("token bucket deny({}):".format(index))
                    print(r)
                    return 0
            if permit == -1:
                print("deny({}):".format(index))
                print(r)
                return 0
            index += 1
        return 1

class TokenBucket():
    update_time = 0.5
    token_num = 0
    def __init__(self,rate):
        if rate < 0:
            self.rate = -1
            return 
        self.rate = rate*self.update_time
        self.maxsize = 2*rate
        self.token_num = 0
    def update(self):
        if self.rate < 0:
            return
        self.token_num += self.rate
        if self.token_num > self.maxsize:
            self.token_num = self.maxsize
    def permit(self,pkt):
        if self.rate < 0:
            
            return 1
        pktsize = len(pkt) - len(pkt.get_header(Ethernet))
        if self.token_num > pktsize:
            self.token_num -= pktsize
            print("token use {},left {}".format(pktsize,self.token_num))
            return 1
        else:
            return 0
    def __str__(self):
        return "token left:{} rate:{}".format(self.token_num,self.rate)
class TokenBucketManager():
    def __init__(self,token_buckets):
        self.token_buckets = token_buckets
        self.last_time = time.time() - 0.5
        self.update_time = 0.5
    def update(self):
        now = time.time()
        if now - self.last_time < self.update_time:
            return 
        self.last_time = now
        for i in self.token_buckets:
            i.update()

def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    firewall = FireWall()
    firewall.read_rule("firewall_rules.txt")
    #firewall.print_rules()
    manager = TokenBucketManager([r.token_bucket for r in firewall.rules])

    while True:
        pkt = None
        try:
            timestamp,input_port,pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break
        manager.update()
        if pkt is not None:
            #log_info("get pkt {}: {}".format(input_port, pkt))

            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            eth = pkt.get_header(Ethernet)
            if eth.ethertype == EtherType.IPv4:
                if not firewall.permit(pkt):
                    #log_info("deny {}".format(1))
                    continue
                #log_info("permit {}".format(1))
            
            net.send_packet(portpair[input_port], pkt)

            
    net.shutdown()
