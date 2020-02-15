from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch 
from mininet.cli import CLI 
from mininet.node import RemoteController
from mininet.node import OVSSwitch


class Phase1_topo( Topo ):
        
    def __init__ ( self ):
        

        Topo.__init__(self)


        h1=self.addHost('h21',ip='100.0.0.11/24', defaultRoute='via 100.0.0.1')
        h2=self.addHost('h22',ip='100.0.0.12/24', defaultRoute='via 100.0.0.1')
        h3=self.addHost('h23',ip='10.0.0.50/24', defaultRoute='via 10.0.0.1')
        h4=self.addHost('h24',ip='10.0.0.51/24', defaultRoute='via 10.0.0.1')
        ds1=self.addHost('ds25',ip='100.0.0.20/24')
        ds2=self.addHost('ds26',ip='100.0.0.21/24')
        ds3=self.addHost('ds27',ip='100.0.0.22/24')
        ws1=self.addHost('ws28',ip='100.0.0.40/24')
        ws2=self.addHost('ws29',ip='100.0.0.41/24')
        ws3=self.addHost('ws30',ip='100.0.0.42/24')
        insp=self.addHost('ins31',ip='100.0.0.30/24')

        sw1=self.addSwitch('s1')
        sw2=self.addSwitch('s2')
        sw3=self.addSwitch('s3')
        sw4=self.addSwitch('s4')
        sw5=self.addSwitch('s5')
        lb1=self.addSwitch('lb6')
        lb2=self.addSwitch('lb7')
        ids=self.addSwitch('id8')
        napt=self.addSwitch('na9')
        fw1=self.addSwitch('fw10')
        fw2=self.addSwitch('fw11')
        self.addLink(h1,sw1)
        self.addLink(h2,sw1)
        self.addLink(sw1,fw1)
        self.addLink(fw1,sw2)
        self.addLink(sw2,fw2)
        self.addLink(fw2,napt)
        self.addLink(sw2,lb1)
        self.addLink(lb1,sw3)
        self.addLink(ds1,sw3)
        self.addLink(ds2,sw3)
        self.addLink(ds3,sw3)
        self.addLink(sw2,ids)
        self.addLink(ids,lb2)
        self.addLink(lb2,sw4)
        self.addLink(ws1,sw4)
        self.addLink(ws2,sw4)
        self.addLink(ws3,sw4)
        
        self.addLink(napt,sw5)
        self.addLink(h3,sw5)
        self.addLink(h4,sw5)
        self.addLink(insp,ids)
        
topology = {'topology' : (lambda : Phase1_topo () )}
if __name__ == "__main__":
    topo=Phase1_topo()
    ctrl=RemoteController ("c0" , ip= "127.0.0.1" , port=6633)


    net=Mininet(
                topo            =   topo,
                switch          =   OVSSwitch,
                controller      =   ctrl,
                autoSetMacs     =   True,
                autoStaticArp   =   True,
                build           =   True,
                cleanup         =   True
                )
    net.start()

    CLI(net)
    
 
    
    
