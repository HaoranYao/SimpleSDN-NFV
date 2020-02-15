//Counts original packets from or to every interface.
pkt_host_in     ::  AverageCounter;
pkt_server_in   ::  AverageCounter;
pkt_server_out  ::  AverageCounter;
pkt_insp_out    ::  AverageCounter;

//Counts ARP packets from or to every interface
arp_req         ::  Counter;
arp_rep         ::  Counter;

//Counts ICMP Ping packets from or to every interface 
icmp_req        ::  Counter;
icmp_rep        ::  Counter;


//Counts TCP Signaling packets from or to every interface
tcp_ack         ::  Counter;
tcp_syn         ::  Counter;
tcp_fin         ::  Counter;
tcp_sack        ::  Counter;
tcp_rst         ::  Counter;

//Counts IP packets.
pkt_ip          ::  Counter;

//Counts HTTP packets
pkt_http_post   ::  Counter;
pkt_http_put    ::  Counter;



//Define input and output operations

to_server       ::  Queue->ToDevice(id8-eth2);
to_host         ::  ToDevice(id8-eth1);
to_insp         ::  Queue->ToDevice(id8-eth3);
from_server     ::  FromDevice(id8-eth2, METHOD LINUX, SNIFFER false);
from_host       ::  FromDevice(id8-eth1, METHOD LINUX, SNIFFER false);

cf_netlayer     ::  Classifier(12/0806 20/0001, //ARP request
                               12/0806 20/0002, //ARP reply
                               12/0800,         //IP packet
                               -);              //other(discard)

                            
cf_ippackets    ::  Classifier(23/01, //ICMP
                               23/06, //TCP
                               -);   //other(discard)

cf_icmp         ::  Classifier(34/01, //Echo reply
                               34/08, //Echo
                               -);   //other(discard)

cf_tcp          ::  Classifier(47/12%12, //ack-syn
                               47/10%10, //ack
                               47/02%02, //syn
                               47/01%01, //fin
                               47/04%04, //rst
                               -);       //other(http)

cf_http         ::  Classifier(66/504F5354, //HTTP Post
                               66/505554,   //HTTP Put
                               -);         //Others(sent to insp)           

cf_put          ::  Classifier(209/636174202f6574632f706173737764, // password
	                           209/636174202f7661722f6c6f672f, //log
	                           208/494E53455254, //INSERT
	                           208/555044415445, //UPDATE
	                           208/44454C455445, //DELETE
                               -);                            




//allow all packets from server
from_server -> Queue -> pkt_server_in -> to_host;
//start processing incoming packets from host
from_host -> pkt_host_in -> cf_netlayer;

//classification from network layer
cf_netlayer[0] -> arp_req -> pkt_server_out -> to_server;
cf_netlayer[1] -> arp_rep -> pkt_server_out -> to_server;
cf_netlayer[2] -> pkt_ip -> cf_ippackets;
cf_netlayer[3] -> pkt_insp_out -> to_insp;

//Classification on IP level
cf_ippackets[0] -> cf_icmp;
cf_ippackets[1] -> cf_tcp;
cf_ippackets[2] -> pkt_insp_out -> to_insp;

//Classification of ICMP packets
cf_icmp[0] -> icmp_rep -> pkt_server_out -> to_server;
cf_icmp[1] -> icmp_req -> pkt_server_out -> to_server;
cf_icmp[2] -> pkt_insp_out -> to_insp;

//Classification of TCP packets
cf_tcp[0] -> tcp_sack -> pkt_server_out -> to_server;
cf_tcp[1] -> tcp_ack -> pkt_server_out -> to_server;
cf_tcp[2] -> tcp_syn -> pkt_server_out -> to_server;
cf_tcp[3] -> tcp_fin -> pkt_server_out -> to_server;                         
cf_tcp[4] -> tcp_rst -> pkt_server_out -> to_server;     
cf_tcp[5] -> cf_http;

//Classification of HTTP packets
cf_http[0] -> pkt_http_post -> pkt_server_out -> to_server;
cf_http[1] -> pkt_http_put -> cf_put;
cf_http[2] -> pkt_insp_out -> to_insp;

//Reject operations
cf_put[0] -> pkt_insp_out -> to_insp;
cf_put[1] -> pkt_insp_out -> to_insp;
cf_put[2] -> pkt_insp_out -> to_insp;
cf_put[3] -> pkt_insp_out -> to_insp;
cf_put[4] -> pkt_insp_out -> to_insp;
cf_put[5] -> pkt_server_out -> to_server;


DriverManager(wait,
                print > ../results/ids.report "===============IDS Report=================",
                print >> ../results/ids.report "Server Input Packet rate(pps):" $(pkt_server_in.rate),
                print >> ../results/ids.report "Host Input Packet rate(pps):" $(pkt_host_in.rate),
                print >> ../results/ids.report "Server Output Packet rate(pps):" $(pkt_server_out.rate),
                print >> ../results/ids.report "Total # of host input packets: " $(pkt_host_in.count),
                print >> ../results/ids.report "Total # of server input packets:" $(pkt_server_in.count),
                print >> ../results/ids.report "Total # of server output packets:" $(pkt_server_out.count),
                print >> ../results/ids.report " ",
                print >> ../results/ids.report "Total # of ARP request packets:" $(arp_req.count),
                print >> ../results/ids.report "Total # of ARP reply packets:" $(arp_rep.count),
                print >> ../results/ids.report " ",
                print >> ../results/ids.report "Total # of icmp echo packets:" $(icmp_req.count),
                print >> ../results/ids.report "Total # of icmp echo-reply packets:" $(icmp_rep.count),
                print >> ../results/ids.report " ",
                print >> ../results/ids.report "Total # of tcp-signaling packets:" $(tcp_ack.count+tcp_sack.count+tcp_fin.count+tcp_rst.count+tcp_syn.count),
                print >> ../results/ids.report "Total # of http packets:" $(pkt_http_post.count+pkt_http_put.count),
                print >> ../results/ids.report "Total # of dropped packets:" $(pkt_insp_out.count),
                stop);

