from pox.core import core
from pox.lib.util import dpid_to_str
from pox.forwarding.l2_learning import LearningSwitch
import pox.openflow.libopenflow_01 as of
from Firewall import Firewall_1
from Firewall import Firewall_2
import os

log = core.getLogger()
class Component1 (object):
    def __init__(self):
        core.openflow.addListeners(self)
        
    
    def _handle_ConnectionUp(self,event):
        dpid=event.dpid
        if dpid==10:
            Firewall_1(event.connection)
        elif dpid==11:
            Firewall_2(event.connection)
        elif dpid==6:
            os.system('sudo /usr/local/bin/click addr=100.0.0.25 \
                                                 eth_server=lb6-eth2\
                                                 eth_client=lb6-eth1\
                                                 dstaddr1=100.0.0.20\
                                                 dstaddr2=100.0.0.21\
                                                 dstaddr3=100.0.0.22\
                                                 IPtype=udp\
                                                 portnum=53\
                                                 filename=lb1.report\
                                                 nfv/lb.click &')   
        elif dpid==7:
            os.system('sudo /usr/local/bin/click addr=100.0.0.45 \
                                                 eth_server=lb7-eth2\
                                                 eth_client=lb7-eth1\
                                                 dstaddr1=100.0.0.40\
                                                 dstaddr2=100.0.0.41\
                                                 dstaddr3=100.0.0.42\
                                                 IPtype=tcp\
                                                 portnum=80\
                                                 filename=lb2.report\
                                                 nfv/lb.click &')    
        elif dpid==8:
            os.system('sudo /usr/local/bin/click ~/assignment/nfv/ids.click &')      
        else:
            LearningSwitch(event.connection,self)
        print("Switch %s has come up."% dpid_to_str(event.dpid))

        

    

    


        



def launch():
    core.registerNew(Component1)

