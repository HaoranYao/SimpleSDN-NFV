
eth1_out, eth1_in, eth2_out, eth2_in :: AverageCounter;
arp_req_ext, arp_req_int, arp_rep_ext, arp_rep_int :: Counter;
// ip_from_ext, ip_from_int :: Counter;
icmp_from_ext, icmp_from_int, service_req :: Counter;
drop_ext, drop_int :: Counter;
drop_ip_ext, drop_ip_int :: Counter;


from_int :: FromDevice(na9-eth2, METHOD LINUX, SNIFFER false);
to_ext :: Queue -> eth1_out -> ToDevice(na9-eth1);
from_ext :: FromDevice(na9-eth1, METHOD LINUX, SNIFFER false);
to_int :: Queue -> eth2_out -> ToDevice(na9-eth2);

arpres_int :: ARPResponder(10.0.0.1 na9-eth2); //respond to internal
arpres_ext :: ARPResponder(100.0.0.1 na9-eth1); //respond to external

arpq_int :: ARPQuerier(10.0.0.1, na9-eth2); //arp querier
arpq_ext :: ARPQuerier(100.0.0.1, na9-eth1); 

int_classifier, ext_classifier :: Classifier(
    12/0806 20/0001, //ARP request
    12/0806 20/0002, //ARP respond
    12/0800, //IP 
    - //rest
)

ip_int_classifier :: IPClassifier(
    tcp or udp, //service
    icmp type echo,
    // icmp type 0,
    // icmp type 8,
    - //rest
)
ip_ext_classifier :: IPClassifier(
    tcp or udp,
    icmp type echo-reply,
    -
)

ip_rewrite :: IPRewriter(pattern 100.0.0.1 20000-65535 - - 0 1); 
ip_icmp_rewrite :: ICMPPingRewriter(pattern 100.0.0.1 20000-65535 - - 0 1);

//packet from external
from_ext -> eth1_in -> ext_classifier;
ext_classifier[0] -> arp_req_ext -> arpres_ext[0] -> to_ext;
ext_classifier[1] -> arp_rep_ext -> [1]arpq_ext;
ext_classifier[2] -> Strip(14) -> CheckIPHeader -> ip_ext_classifier;
ext_classifier[3] -> drop_ext -> Discard;

ip_ext_classifier[0] -> ip_rewrite[1] -> [0]arpq_int -> to_int;
ip_ext_classifier[1] -> icmp_from_ext -> ip_icmp_rewrite[1] -> [0]arpq_int -> to_int;
ip_ext_classifier[2] -> drop_ip_ext -> Discard;

//packet from internal
from_int -> eth2_in -> int_classifier;
int_classifier[0] -> arp_req_int -> arpres_int[0] -> to_int;
int_classifier[1] -> arp_rep_int -> [1]arpq_int;
int_classifier[2] -> Strip(14) -> CheckIPHeader -> ip_int_classifier;
int_classifier[3] -> drop_int -> Discard;

ip_int_classifier[0] -> service_req -> ip_rewrite[0] -> [0]arpq_ext -> to_ext;
ip_int_classifier[1] -> icmp_from_int -> ip_icmp_rewrite[0] -> [0]arpq_ext -> to_ext;
ip_int_classifier[2] -> drop_ip_int -> Discard;

DriverManager(wait, print > ../../results/napt.report "
        ===================== NAPT Report ====================
        Input Packet Rate (pps): $(add $(eth1_in.rate) $(eth2_in.rate))
        Output Packet Rate(pps): $(add $(eth1_out.rate) $(eth2_out.rate))
        
        Total # of input packets: $(add $(eth1_in.count) $(eth2_in.count))
        Total # of output packets: $(add $(eth1_out.count) $(eth2_out.count))
        
        Total # of ARP request packets: $(add $(arp_req_int.count) $(arp_req_ext.count))
        Total # of ARP reply packets: $(add $(arp_rep_int.count) $(arp_rep_ext.count))
        
        Total # of service requests packets: $(add $(service_req))
        Total # of ICMP packets: $(add $(icmp_from_int.count) $(icmp_from_ext.count))
        Total # of dropped packets: $(add $(drop_in.count) $(drop_ip_in.count) $(drop_ext.count) $(drop_ip_ext.count))
        ======================================================", stop);






