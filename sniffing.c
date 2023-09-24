#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* Ethernet header */
struct ethheader {
  unsigned char ether_dhost[6]; /* destination host address */
  unsigned char ether_shost[6]; /* source host address */
  unsigned short int ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* TCP Header */
// struct unsigned int tcp_seq;

struct tcpheader {
	unsigned short int th_sport;
	unsigned short int th_dport;
	unsigned int th_seq;
	unsigned int th_ack;
	unsigned char th_offx2;
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	unsigned char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        unsigned short int th_win;
        unsigned short int th_sum;
        unsigned short int th_urp;
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/*
 * print data in rows of 16 bytes: offset hex ascii
 *
 */
void print_hex_ascii_line(const u_char *payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("\t\t\t\t%05d   ",offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len;i++) {
        printf("%02x ",*ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if(len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if(len < 16){
        gap = 16 - len;
        for (i = 0; i< gap;i++){
            printf("  ");
        }
    }
    printf("  ");

    /* ascii (if printable) */
    ch = payload;
    for(i=0;i<len;i++){
        if(isprint(*ch))
            printf("%c",*ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_message(const u_char *payload,int len){
    int len_rem = len;
    int line_width = 16;     /* number of bytes per line */
    int line_len;
    int offset = 0;          /* zero-based offset counter */
    const u_char *ch = payload;

    if(len <= 0)
        return;

    /* data fits no one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch,len,offset);
        return;
    }

    /* data spans multiple lines */
    for ( ; ;){
        /*compute current line lenght */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch,line_len,offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if(len_rem <= line_width){
            /* print last line and get out */
            print_hex_ascii_line(ch,len_rem,offset);
            break;
        }
    }
    return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
	const struct ethheader *eth;
	const struct ipheader *ip;
	const struct tcpheader *tcp;
	const char *message;
	int size_message;

	eth = (struct ethheader *)packet;
        ip = (struct ipheader*)(packet + sizeof(struct ethheader)); // 패킷의 첫 시작 지점 + Ethernet 크기 = IP 시작점 //

	if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
		/* determine protocol */
		switch(ip->iph_protocol) {                                 
	        case IPPROTO_TCP:
			printf("#########################################################################\n");
        		printf("Protocol: TCP\n");
			
        	       	printf("Source MAC Address : %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost)); // Source MAC Address 출력 //
	                printf("Destination MAC Address : %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost)); // Destination MAC Address 출력

        	        printf("\tSource IP Address : %s\n", inet_ntoa(ip->iph_sourceip)); // Source IP Address 출력 //
	                printf("\tDestination IP Address : %s\n", inet_ntoa(ip->iph_destip)); // Destination IP Address 출력 //


			tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + sizeof(struct ipheader)); // 패킷의 첫 시작 지점 + Ethernet 크기 + IP 크기 = TCP 시작점 //

			printf("\t\tSource Port: %d\n", ntohs(tcp->th_sport)); // Source Port 출력
			printf("\t\tDestination Port: %d\n", ntohs(tcp->th_dport)); // Destination Port 출력
			
			message = (unsigned char *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + sizeof(struct tcpheader));
			size_message = ntohs(ip->iph_len) - (sizeof(struct ipheader) + sizeof(struct tcpheader));
			if(size_message > 0){
				if(size_message > 30) size_message = 30;
				printf("\t\t\tMessage (%d bytes) :\n", size_message);
				print_message(message, size_message);
    			}
			return;
	        case IPPROTO_UDP:
        		printf("   Protocol: UDP\n");
		        return;
	        case IPPROTO_ICMP:
        		printf("   Protocol: ICMP\n");
		        return;
	        default:
        		printf("   Protocol: others\n");
		        return;
		}
	}
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}

