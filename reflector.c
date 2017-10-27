#include <stdio.h>
#include <pcap.h>
#include <getopt.h>

int main(int argc, char *argv[])
{
	char *victim_ip = NULL;
	char *victim_eth = NULL;
	char *relayer_ip = NULL;
	char *relayer_eth = NULL;
	char *interface = "eth0";
	

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

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	return(0);
}
