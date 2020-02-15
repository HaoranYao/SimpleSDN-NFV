// addr, eth_server, eth_client, dstaddr, IPtype, portnum, $filename needs to be defined


inputclientcount, inputservercount, outputclientcount, outputservercount ::AverageCounter;
ARPquecount, ARPquecount1, ARPrescount, ARPrescount1, ICMPcount, IPcount, IPcount1, dropcount, dropcount1, dropcount2 ::Counter;


Fromclient :: FromDevice($eth_client, METHOD LINUX, SNIFFER false);
Fromserver :: FromDevice($eth_server, METHOD LINUX, SNIFFER false);


outtoserver :: ToDevice($eth_server, METHOD LINUX);
outtoclient :: ToDevice($eth_client, METHOD LINUX);
Toserver :: Queue -> outputservercount -> outtoserver;
Toclient :: Queue -> outputclientcount -> outtoclient;

clientclassifier, serverclassifier :: Classifier(12/0806 20/0001 //ARP requrest
                            , 12/0806 20/0002 // ARP reply
                            , 12/0800 //IP 
                            , - ); //others

ICMPres :: ICMPPingResponder ();
ARPres_server_count :: Counter //useless one to test ARPresponder to server
ARPres_client :: ARPResponder($addr $eth_client);//addr,eth_client
ARPres_server :: ARPResponder($addr $eth_server);//addr,eth_server


ARPque_toserver_count :: Counter; //useless since client will not send reply through port 1
ARPque_toserver :: ARPQuerier($addr, $eth_server);//addr,eth_server
ARPque_toclient :: ARPQuerier($addr, $eth_client);//addr,eth_client


Robin :: RoundRobinIPMapper($addr - $dstaddr1 - 0 1,
                            $addr - $dstaddr2 - 0 1,
                            $addr - $dstaddr3 - 0 1);//addr, dstaddr
IPrewrite :: IPRewriter (Robin);
IPpkt_toserver :: GetIPAddress(16) -> CheckIPHeader -> [0]ARPque_toserver -> Toserver;
IPpkt_toclient :: GetIPAddress(16) -> CheckIPHeader -> [0]ARPque_toclient -> Toclient;


IPrewrite[0] -> IPpkt_toserver;
IPrewrite[1] -> IPpkt_toclient;


IPPKTclassifier :: IPClassifier (dst $addr and icmp, //ICMP
                                dst $addr port $portnum and $IPtype, //addr, IPtype, portnum
                                -);


//From client
Fromclient -> inputclientcount -> clientclassifier;
clientclassifier[0] -> ARPrescount -> ARPres_client -> Toclient;
clientclassifier[1] -> ARPquecount -> [1]ARPque_toclient;
clientclassifier[2] -> IPcount -> Strip(14) -> CheckIPHeader -> IPPKTclassifier;
    IPPKTclassifier[0] -> ICMPcount -> ICMPres -> IPpkt_toclient;
    IPPKTclassifier[1] -> [0]IPrewrite;
    IPPKTclassifier[2] -> dropcount -> Discard;
clientclassifier[3] -> dropcount1 -> Discard;


//From server
Fromserver -> inputservercount -> serverclassifier;
serverclassifier[0] -> ARPrescount1 -> ARPres_server_count -> ARPres_server -> Toserver;
serverclassifier[1] -> ARPquecount1 -> ARPque_toserver_count -> [1]ARPque_toserver;
serverclassifier[2] -> IPcount1 -> Strip(14) -> CheckIPHeader -> [0]IPrewrite;
serverclassifier[3] -> dropcount2 -> Discard;


//Write report
DriverManager(wait, print > ../results/$filename "
================report===============
   Input Packet Rate (pps):  $(add $(inputclientcount.rate) $(inputservercount.rate))
  Output Packet Rate (pps):  $(add $(outputclientcount.rate) $(outputservercount.rate))
                    
Total # of    input packet:  $(add $(inputclientcount.count) $(inputservercount.count))
Total # of   output packet:  $(add $(outputclientcount.count) $(outputservercount.count))
                    
Total # of    ARP requests:  $(add $(ARPrescount.count) $(ARPrescount1.count))
Total # of   ARP responses:  $(add $(ARPquecount.count) $(ARPquecount1.count))
                    
Total # of service packets:  $(add $(IPcount.count) $(IPcount1.count))
Total # of    ICMP packets:  $(ICMPcount.count))
Total # of dropped packets:  $(add $(dropcount.count) $(dropcount1.count) $(dropcount2.count))
======================================",
stop);

