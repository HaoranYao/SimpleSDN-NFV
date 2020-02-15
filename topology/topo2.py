from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch 
from mininet.cli import CLI 
from mininet.node import RemoteController
from mininet.node import OVSSwitch
import os


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
    reportPath = os.path.expanduser('~')+"/IK2220_phase1/results/phase_1_report"
    report = open(reportPath,'w')
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
    h21 = net.get('h21')
    h22 = net.get('h22')
    h23 = net.get('h23')
    h24 = net.get('h24')

    ws1 = net.get('ws28')
    ws2 = net.get('ws29')
    ws3 = net.get('ws30')
    ds1 = net.get('ds25')
    ds2 = net.get('ds26')
    ds3 = net.get('ds27')





    ds1.cmd('python dns1.py &')
    ds2.cmd('python dns2.py &')
    ds3.cmd('python dns3.py &')


   
    res=0
    report.write('\nICMP test started:')
    print('ICMP test started:')
    report.write('\nSending ICMP request from puz to puz')
    print('Sending ICMP request from puz to puz')
    s=h21.cmd('ping %s -c 1'%h22.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received. correct!!')
        print('Response received.')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')
        print('Response not received.')


    report.write('\nSending ICMP request from puz to prz')
    print('Sending ICMP request from puz to prz')

    s=h21.cmd('ping %s -c 1'%h23.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received.wrong')
        print('Response received.')

        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending ICMP request from prz to prz')
    s=h23.cmd('ping %s -c 1'%h24.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending ICMP request from prz to puz')
    s=h23.cmd('ping %s -c 1'%h21.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')


    report.write('\nSending ICMP request from puz to web server')
    s=h21.cmd('ping %s -c 1'%ws1.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending ICMP request from puz to dns server')
    s=h21.cmd('ping %s -c 1'%ds1.IP())
    if s.find('1 received') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    res2=res/6.0


    report.write('\n\n\n\n\n\n\n')



    res=0
    report.write('\nTCP test started:')
    report.write('\nSending telnet request from h1 to WS1 port 80')


    s=h21.cmd('telnet %s 80'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')


    report.write('\nSending telnet request from h1 to WS2 port 80')
    s=h21.cmd('telnet %s 80'%ws2.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending telnet request from h1 to WS3 port 80')
    s=h21.cmd('telnet %s 80'%ws3.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending telnet request from h1 to WS1 port 100')
    s=h21.cmd('telnet %s 100'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending telnet request from h1 to WS2 port 100')
    s=h21.cmd('telnet %s 100'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending telnet request from h1 to WS3 port 100')
    s=h21.cmd('telnet %s 100'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending telnet request from h3 to WS1 port 80')
    s=h23.cmd('telnet %s 80'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending telnet request from h3 to WS1 port 100')
    s=h23.cmd('telnet %s 100'%ws1.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending telnet request from puz to prz')
    s = h21.cmd('telnet %s 100' % h23.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.wrong')
        res = res + 1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending telnet request from prz to puz')
    s = h23.cmd('telnet %s 100' % h21.IP())
    if s.find('refused') > -1:
        report.write('\nResponse received.correct!!')
        res = res + 1
    else:
        report.write('\nResponse not received.wrong')



    report.write('\n\n\n\n\n\n\n')

    ws1.cmd('python3 -m http.server 80 &')
    ws2.cmd('python3 -m http.server 80 &')
    ws3.cmd('python3 -m http.server 80 &')

    res=0
    report.write('\nUDP test started:')
    report.write('\nSending DNS request from h1 to DS1 port 53')
    s=h21.cmd('dig @100.0.0.20 sdn1.com')
    if s.find('Got answer') > -1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending DNS request from h1 to DS2 port 53')
    s=h21.cmd('dig @100.0.0.21 sdn2.com')
    if s.find('Got answer')>-1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending DNS request from h1 to DS3 port 53')
    s=h21.cmd('dig @100.0.0.22 sdn3.com')
    if s.find('Got answer')>-1:
        report.write('\nResponse received.correct!!')
        res=res+1
    else:
        report.write('\nResponse not received.wrong')

    report.write('\nSending DNS request from h1 to DS1 port 100')
    s=h21.cmd('dig @100.0.0.20 -p 100 sdn1.com')
    if s.find('Got answer')>-1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending DNS request from h1 to DS2 port 100')
    s=h21.cmd('dig @100.0.0.21 -p 100 sdn2.com')
    if s.find('Got answer')>-1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')

    report.write('\nSending DNS request from h1 to DS3 port 100')
    s=h21.cmd('dig @100.0.0.22 -p 100 sdn3.com')
    if s.find('Got answer')>-1:
        report.write('\nResponse received.wrong')
        res=res+1
    else:
        report.write('\nResponse not received.correct!!')


    report.write('\nSending UDP packet from puz to prz port 1000')
    h23.cmd('iperf -s -u -p 1000 &')
    s = h21.cmd('iperf -u -c 100.0.0.51 -p 1000 -t 1 -n 1')
    if s.find('WARNING:') > -1:
        report.write('\nResponse not received.correct!!')
    else:
        report.write('\nResponse received.wrong')

    report.write('\nSending UDP packet from prz to puz port 1000')
    h21.cmd('iperf -s -u -p 1000 &')
    s = h23.cmd('iperf -u -c 100.0.0.51 -p 1000 -t 1 -n 1')
    if s.find('WARNING:') > -1:
        report.write('\nResponse not received.wrong')
    else:
        report.write('\nResponse received.correct!!')


    report.write('\n\n\n\n\n\n\n')
    report.write('\nHTTP test starts:')
    report.write(h21.cmd('wget 100.0.0.40:80'))
    report.close()

    CLI(net)
    
 
    
    
