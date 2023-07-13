#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_ADDR_LEN 6
#define ETHERTYPE_IP 0x0800
#define IPTYPE_TCP 0x6

struct libnet_ethernet_hdr
{
    u_int8_t ether_dhost[ETHER_ADDR_LEN];
    u_int8_t ether_shost[ETHER_ADDR_LEN];
    u_int16_t ether_type; /* next header type (ipv4,arp,ipv6 etc) */
};

struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl : 4,      /* header length */
        ip_v : 4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v : 4,       /* version */
        ip_hl : 4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */ /* next header protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2 : 4,         /* (unused) */
        th_off : 4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off : 4,        /* data offset */
        th_x2 : 4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void printMac(u_int8_t* m)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7]);
}
void printIP(struct in_addr src_ip, struct in_addr dst_ip)
{
    printf("%d.%d.%d.%d\t\t%d.%d.%d.%d", (src_ip.s_addr) & 0xff,(src_ip.s_addr>>8) & 0xff,(src_ip.s_addr>>16) & 0xff,(src_ip.s_addr>>24) & 0xff,(dst_ip.s_addr) & 0xff,(dst_ip.s_addr>>8) & 0xff,(dst_ip.s_addr>>16) & 0xff,(dst_ip.s_addr>>24) & 0xff);
}
void printTCP(u_int16_t tcp)
{
    printf("%d",ntohs(tcp));
}
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
        .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        int i,cnt;
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        header->caplen;
        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
        struct libnet_ipv4_hdr* ipv4_hdr = (struct libnet_ipv4_hdr*)(packet + sizeof(*eth_hdr));
        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet+sizeof(*eth_hdr)+sizeof(*ipv4_hdr));
        int header_size = sizeof(*eth_hdr)+sizeof(*ipv4_hdr)+sizeof(*tcp_hdr); // for payload
        
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
            if (ipv4_hdr->ip_p == IPTYPE_TCP) {
                printf("- - - - - - - - - - - - - - - - - - - - - -\n");
                printf("\n%u bytes captured\n", header->caplen);
            	printMac(eth_hdr->ether_shost);
        	printf("\t");
        	printMac(eth_hdr->ether_dhost);
        	printf("\n");
        	printIP(ipv4_hdr->ip_src, ipv4_hdr->ip_dst);
        	printf("\n");
     	   	printTCP(tcp_hdr->th_sport);
       	 	printf("\t\t\t");
        	printTCP(tcp_hdr->th_dport);
        	printf("\n");
        	if(header->caplen > header_size) { // 10byte print
        		printf("paload : ");
        		cnt = header->caplen-header_size;
			if(cnt>10) {
				cnt = 10; // 10byte over
			}
        		while(cnt>0){
        			printf("%02x ",*((packet+header_size++))); //packet pointer ++
				cnt--;
        		}
        		printf("\n\n- - - - - - - - - - - - - - - - - - - - - -\n");
        	} else {
        		printf("\n- - - - - - - - - - - - - - - - - - - - - -\n");
        		continue;
        	}
            } 
        } else {
        continue;
        }
    }

    pcap_close(pcap);
}
