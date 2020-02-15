from pox.core import core
from pox.forwarding.l2_learning import LearningSwitch
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import thread
import time
class Firewall(LearningSwitch):

    def __init__(self, connection):
        self.tcprules = {}
        self.udprules = {}
        self.icmprules = {}
        self.arprules = {}
        self.DNSpool = (IPAddr('100.0.0.25'),)
        self.Webpool = (IPAddr('100.0.0.45'),)
        self.Publicpool = (IPAddr('100.0.0.12'),IPAddr('100.0.0.11'))
        self.Privatepool = (IPAddr('100.0.0.1'),)
        LearningSwitch.__init__(self, connection,False)

    def addtcprules(self,scr, dst, ACK, dstport):
        self.tcprules[(scr,dst)] = (ACK, dstport)

    def addudprules(self, scr, dst, dstport, allow):
        self.udprules[(scr, dst)] = [dstport, allow]

    def addicmprules(self, dst,code):
        self.icmprules[dst,code] = True
        
    def addtcppool2pool(self,srcpool, dstpool, ACK, dsport):
        for i in srcpool:
            for j in dstpool:
                self.addtcprules(i,j,ACK,dsport)

    def addudppool2pool(self,srcpool,dstpool, allow, dsport):
        for i in srcpool:
            for j in dstpool:
                self.addudprules(i,j,dsport,allow)

    def addicmppool(self,icmppool,code):
        for i in icmppool:
            self.addicmprules(i,code)

    def changetimer(self,srcaddr,dsaddr):
        # one second of delay
        time.sleep(10)
        self.addudprules(srcaddr, dsaddr, -1, 0)



    def checktcp(self, packet): #packet = event.parsed.find('tcp')
        dsaddr = packet.dstip
        dsport = packet.find('tcp').dstport
        srcaddr = packet.srcip
        ack=packet.find('tcp').ack
        try:#Use try-except for exceptions when not able to find a value
            if ack >= self.tcprules[(srcaddr,dsaddr)][0] and ((self.tcprules[(srcaddr,dsaddr)][1] == dsport or self.tcprules[(srcaddr,dsaddr)][1]== -1)):
                # with other destination address which the its port is not specified, we set the port number in the rules to -1
                return True
            else:
                return False
        except KeyError:
            return False

    def checkudp(self,packet):
        dsaddr = packet.dstip
        dsport = packet.find('udp').dstport
        srcaddr = packet.srcip
        try:
            if (self.udprules[(srcaddr,dsaddr)][0] == dsport or self.udprules[(srcaddr,dsaddr)][0] == -1) and self.udprules[(srcaddr,dsaddr)][1] == 1:
                #when the time runs out, change the rule back to (dsaddr, srcaddr,-1,0)
                if srcaddr in self.Privatepool:
                    self.addudprules(dsaddr,srcaddr,-1, 1)
                    thread.start_new_thread(self.changetimer, (dsaddr, srcaddr))

                return True
            else:
                return False
        except KeyError:
            return False

    def checkicmp(self,packet):
        print('ICMP Packet found from {0} to {1} :'.format(packet.srcip,packet.dstip))
        try:
            if self.icmprules[packet.dstip,packet.find('icmp').type] != None :
                print(' Forwarded')
                return True
            else:
                print(' Blocked')
                return False
        except KeyError:
            print(' Blocked')
            return False

    def _handle_PacketIn(self, event):
        Packetin = event.parsed

        def drop(duration=None):
            if duration is not None:
                if not isinstance(duration, tuple):
                    duration = (duration, duration)
                msg = of.ofp_flow_mod()
                msg.match = of.ofp_match.from_packet(packet)
                msg.idle_timeout = duration[0]
                msg.hard_timeout = duration[1]
                msg.buffer_id = event.ofp.buffer_id
                self.connection.send(msg)
            elif event.ofp.buffer_id is not None:
                msg = of.ofp_packet_out()
                msg.buffer_id = event.ofp.buffer_id
                msg.in_port = event.port
                self.connection.send(msg)
        if Packetin.find('ipv4'):#Find if it is IPv4 Packet first
            Packetin=Packetin.find('ipv4')
            if Packetin.find('tcp'):
                if self.checktcp(Packetin.find('ipv4')):
                    super(Firewall, self)._handle_PacketIn(event)
                    return


            elif Packetin.find('udp'):
                if self.checkudp(Packetin.find('ipv4')):
                    super(Firewall, self)._handle_PacketIn(event)
                    return


            elif Packetin.find('icmp'):
                if self.checkicmp(Packetin.find('ipv4')):#Only original IPv4 Packet contains IPaddr information
                    super(Firewall, self)._handle_PacketIn(event)
                    return


            
        elif Packetin.find('arp'):
                packet = Packetin.find('arp')
                if packet.opcode == packet.REPLY or packet.opcode == packet.REQUEST:
                    super(Firewall, self)._handle_PacketIn(event)
                    return
        else:
            drop()
            return



class Firewall_1(Firewall):
    def __init__(self,connection):
        Firewall.__init__(self,connection)
        self.addicmppool(self.Publicpool, 0)
        self.addicmppool(self.Publicpool, 8)
        self.addicmppool(self.Privatepool,0)
        self.addicmppool(self.DNSpool, 0)
        self.addicmppool(self.DNSpool, 8)
        self.addicmppool(self.Webpool, 0)
        self.addicmppool(self.Webpool, 8)

        # allow incoming TCP connect from prz
        self.addtcppool2pool(self.Privatepool,self.Publicpool,0,-1)
        # allow incoming TCP connect from DNS and Web server
        self.addtcppool2pool(self.Webpool,self.Publicpool,0,-1)
        self.addtcppool2pool(self.DNSpool,self.Publicpool,0,-1)
        # allow TCP init to prz
        self.addtcppool2pool(self.Publicpool,self.Privatepool,0,-1)
        # allow TCP init to DNS and Web server
        self.addtcppool2pool(self.Publicpool,self.DNSpool,0,53)
        self.addtcppool2pool(self.Publicpool,self.Webpool,0,80)


        # allow incoming udp connect from prz
        self.addudppool2pool(self.Privatepool,self.Publicpool,1,-1)
        # allow incoming udp connect from DNS and Web server
        self.addudppool2pool(self.Webpool, self.Publicpool, 1, -1)
        self.addudppool2pool(self.DNSpool, self.Publicpool, 1, -1)
        # allow udp init to DNS and Web server
        self.addudppool2pool(self.Publicpool, self.Webpool, 1, 80)
        self.addudppool2pool(self.Publicpool, self.DNSpool, 1, 53)
        # allow udp init to prz
        self.addudppool2pool(self.Publicpool, self.Privatepool, 1, -1)
class Firewall_2(Firewall):
    def __init__(self,connection):
        Firewall.__init__(self,connection)
        #allow ping to puz
        self.addicmppool(self.Publicpool, 0)
        self.addicmppool(self.Publicpool, 8)
        self.addicmppool(self.Privatepool, 0)
        self.addicmppool(self.Privatepool, 8)
        self.addicmppool(self.DNSpool, 0)
        self.addicmppool(self.DNSpool, 8)
        self.addicmppool(self.Webpool, 0)
        self.addicmppool(self.Webpool, 8)


        #allow incoming TCP response from puz
        self.addtcppool2pool(self.Publicpool,self.Privatepool,1,-1)
        #allow incoming TCP response from DNS and Web server
        self.addtcppool2pool(self.DNSpool,self.Privatepool,1,-1)
        self.addtcppool2pool(self.Webpool,self.Privatepool,1,-1)
        #allow TCP init to puz
        self.addtcppool2pool(self.Privatepool,self.Publicpool,0,-1)
        #allow TCP init to DNS and Web server
        self.addtcppool2pool(self.Privatepool,self.DNSpool,0,53)
        self.addtcppool2pool(self.Privatepool,self.Webpool,0,80)


        # allow incoming udp connect from puz
        self.addudppool2pool(self.Publicpool, self.Privatepool,0,-1)
        # allow incoming udp connect from DNS and Web server
        self.addudppool2pool(self.Webpool, self.Privatepool, 0, -1)
        self.addudppool2pool(self.DNSpool, self.Privatepool, 0, -1)
        # allow udp init to DNS and Web server
        self.addudppool2pool(self.Privatepool, self.Webpool, 1, 80)
        self.addudppool2pool(self.Privatepool, self.DNSpool, 1, 53)
        # allow udp init to puz
        self.addudppool2pool(self.Privatepool, self.Publicpool, 1, -1)