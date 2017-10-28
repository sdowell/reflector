#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
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

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	printf("Received packet\n");
	const struct sniff_ethernet *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const struct sniff_tcp *tcp; /* The TCP header */
	const char *payload; /* Packet payload */

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
	
	// Record source and dest addresses
	const char *aux = inet_ntoa(ip->ip_src);
	const char *s_ipad = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = inet_ntoa(ip->ip_dst);
	const char *d_ipad = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = ether_ntoa((struct ether_addr *)ethernet->ether_shost);
	const char *s_host = strcpy((char *) malloc(strlen(aux)+1), aux);
	aux = ether_ntoa((struct ether_addr *)ethernet->ether_dhost);
	const char *d_host = strcpy((char *) malloc(strlen(aux)+1), aux);   
	
	
	printf("Source IP: %s, Source eth: %s\nDest IP: %s, Dest eth: %s\n", 
	       s_ipad, s_host, d_ipad, d_host);
	       //inet_ntoa(ip->ip_src), ether_ntoa(ethernet->ether_shost), inet_ntoa(ip->ip_dst),ether_ntoa(ethernet->ether_dhost));
	//delete[] s_ipad; delete[] d_ipad;delete[] s_host; delete[] d_host;
	free(s_ipad);
	free(s_host);
	free(d_ipad);
	free(d_host);
	/* Print payload in ASCII */
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
        printf("\n");
    }
    
	return;	
}

int main(int argc, char *argv[])
{
	char *victim_ip = NULL;
	char *victim_eth = NULL;
	char *relayer_ip = NULL;
	char *relayer_eth = NULL;
	char *interface = "eth0";
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 8000";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

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
	
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	// define the device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
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
