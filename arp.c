#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/filter.h> // CHANGE: include lsf
#include <net/ethernet.h>
#include <pcap/pcap.h>

#define INTERFACE "eth0"
#define DEBUG 1
#define ETH_HDR_LEN 14
#define BUFF_SIZE 2048
#define ETHER_TYPE_FOR_ARP 0x0806
#define HW_TYPE_FOR_ETHER 0x0001
#define OP_CODE_FOR_ARP_REQ 0x0001
#define HW_LEN_FOR_ETHER 0x06
#define HW_LEN_FOR_IP 0x04
#define PROTO_TYPE_FOR_IP 0x0800
#define DEFAULT_DEVICE "eth0"

typedef unsigned char byte1;
typedef uint16_t byte2;
typedef uint32_t byte4;

typedef struct arp_packet
{
	// ETH Header
	byte1 dest_mac[6];
	byte1 src_mac[6];
	byte2 ether_type;
	// ARP Header
	byte2 hw_type;
	byte2 proto_type;
	byte1 hw_size;
	byte1 proto_size;
	byte2 arp_opcode;
	byte1 sender_mac[6];
	byte1 sender_ip[4];
	byte1 target_mac[6];
	byte1 target_ip[4];
	// Paddign
	char padding[18];
}ARP_PKT;


struct ethernet {
    unsigned char dest[6];
    unsigned char source[6];
    uint16_t eth_type;
};

struct arp {
    byte2 htype;
    byte2 ptype;
    byte1 hlen;
    byte1 plen;
    byte2 oper;
    /* addresses */
   	byte1 sender_ha[6];
    unsigned char sender_pa[4];
    byte1 target_ha[6];
    unsigned char target_pa[4];
};


void debug(ARP_PKT pkt){

    uint16_t htype = ntohs(pkt.hw_type);
    uint16_t ptype = ntohs(pkt.proto_type);
    uint16_t oper = ntohs(pkt.arp_opcode);
    switch(htype)
    {
        case 0x0001:
            printf("ARP HTYPE: Ethernet(0x%04X)\n", htype);
            break;
        default:
            printf("ARP HYPE: 0x%04X\n", htype);
            break;
    }
    switch(ptype)
    {
        case 0x0800:
            printf("ARP PTYPE: IPv4(0x%04X)\n", ptype);
            break;
        default:
            printf("ARP PTYPE: 0x%04X\n", ptype);
            break;
    }

    switch(oper)
    {
        case 0x0001:
            printf("ARP OPER: Request(0x%04X)\n", oper);
            break;
        case 0x0002:
            printf("ARP OPER: Response(0x%04X)\n", oper);
            break;
        default:
            printf("ARP OPER: 0x%04X\n", oper);
            break;
    }
    printf("ARP Sender HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           pkt.src_mac[0],pkt.src_mac[1],pkt.src_mac[2],
           pkt.src_mac[3], pkt.src_mac[4], pkt.src_mac[5]);
    printf("ARP Target HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           pkt.target_mac[0],pkt.target_mac[1],pkt.target_mac[2],
           pkt.target_mac[3], pkt.target_mac[4], pkt.target_mac[5]);
    printf("ARP DONE =====================\n");
}



//arp filter. Dont know exactly what it do,but IT WORKS!!!!
struct sock_filter arpfilter[] = {
    BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12), /* Skip 12 bytes */
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETH_P_ARP, 0, 1), /* if eth type != ARP
                                                         skip next instr. */
    BPF_STMT(BPF_RET+BPF_K, sizeof(struct arp) +
                 sizeof(struct ethernet)),
    BPF_STMT(BPF_RET+BPF_K, 0), /* Return, either the ARP packet or nil */
};

int main(void)
{
	int sniff_socket;
	void * buffer;
	ssize_t recvd_size;
	struct ethernet *eth_hdr;
	struct arp *arp_hdr;
	struct sock_filter *filter;
	struct sock_fprog fprog;
	ARP_PKT pkt;
	int if_fd;
	struct ifreq ifr;
	struct sockaddr_ll sa;
	int retVal;
	int i;
	int sock;
	/*********************Initialice arp packet*********************************/
	if_fd = socket(AF_INET, SOCK_STREAM, 0);
	if( if_fd < 0 )
	{
		perror("IF Socket");
		exit(-1);
	} 
	
	/*Get Mac hw*/
	memcpy(ifr.ifr_name, INTERFACE , IF_NAMESIZE);
	retVal = ioctl(if_fd, SIOCGIFHWADDR, &ifr, sizeof(ifr));
	if( retVal < 0 )
	{
		perror("IOCTL hw");
		close(if_fd);
		exit(-1);
	}
	
	
	//Formulate arp reply
	// Ethernet Header
	memset(pkt.src_mac+0, (ifr.ifr_hwaddr.sa_data[0]&0xFF), (sizeof(byte1)));
	memset(pkt.src_mac+1, (ifr.ifr_hwaddr.sa_data[1]&0xFF), (sizeof(byte1)));
	memset(pkt.src_mac+2, (ifr.ifr_hwaddr.sa_data[2]&0xFF), (sizeof(byte1)));
	memset(pkt.src_mac+3, (ifr.ifr_hwaddr.sa_data[3]&0xFF), (sizeof(byte1)));
	memset(pkt.src_mac+4, (ifr.ifr_hwaddr.sa_data[4]&0xFF), (sizeof(byte1)));
	memset(pkt.src_mac+5, (ifr.ifr_hwaddr.sa_data[5]&0xFF), (sizeof(byte1)));
	pkt.ether_type = htons(ETHER_TYPE_FOR_ARP);
	
	//Arp construction
	pkt.hw_type = htons(HW_TYPE_FOR_ETHER);
	pkt.proto_type = htons(PROTO_TYPE_FOR_IP);
	pkt.hw_size = HW_LEN_FOR_ETHER;
	pkt.proto_size = HW_LEN_FOR_IP;
	pkt.arp_opcode = htons(0X0002);
	memcpy(pkt.sender_mac, pkt.src_mac, (6 * sizeof(byte1)));
	
	// Padding
	memset(pkt.padding, 0 , 18 * sizeof(char));
	
	//Device information
	retVal = ioctl(if_fd, SIOCGIFADDR, &ifr, sizeof(ifr));
	if( retVal < 0 )
	{
		perror("IOCTL ip");
		close(if_fd);
		exit(-1);
	}
	close (if_fd);
	

	/*Getting interface info*/
	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_protocol = htons(ETH_P_ARP);
	sa.sll_halen = 0;
	
	/********************Finish the initialation***************************/
	
	//Starting the socket
	if ((sniff_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
	{
		perror("socket(): ");
		exit(-1);
	}
	
	//Preparing the filter
	if ((filter = malloc(sizeof(arpfilter))) == NULL) {
		perror("malloc");
		close(sock);
		exit(-1);
	}	
	memcpy(filter, &arpfilter, sizeof(arpfilter));
	fprog.filter=filter;
	fprog.len=sizeof(arpfilter)/sizeof(struct sock_filter);
	
	//Add socket filter
	if ( setsockopt(sniff_socket,SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) )
	{
		perror("Setsocketopt");
		close(sock);
		exit(-1);
	}
	//Starting sniffing all arp packets
	buffer = malloc(BUFF_SIZE);
	while(1)
	{
		printf("Starting capturing arp...\n");
		if ( ( recvd_size = recv ( sniff_socket,buffer, BUFF_SIZE, 0)) < 0)
		{
			perror("recv()");
			free(buffer);
			close(sock);
			exit(-1);
		}

		//We have arp packet but we might add ethernet header
		if((size_t)recvd_size < (sizeof(struct ethernet) + sizeof(struct arp)))
        	{
            		printf("Short packet. Packet len: %ld, Check the filter\n", recvd_size);
            		break;
       		}	
		//Adding the ethernet size
		arp_hdr = (struct arp *)(buffer+ETH_HDR_LEN);
		//Next func process the packet
		
		/******************Process the packet**************/
		if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP)))==-1){
			perror("Error Creating ARP socket");
			exit(-1);
		}
	
		memset(pkt.dest_mac+0, (arp_hdr->sender_ha[0]&0xFF), (sizeof(byte1)));
		memset(pkt.dest_mac+1, (arp_hdr->sender_ha[1]&0xFF), (sizeof(byte1)));
		memset(pkt.dest_mac+2, (arp_hdr->sender_ha[2]&0xFF), (sizeof(byte1)));
		memset(pkt.dest_mac+3, (arp_hdr->sender_ha[3]&0xFF), (sizeof(byte1)));
		memset(pkt.dest_mac+4, (arp_hdr->sender_ha[4]&0xFF), (sizeof(byte1)));
		memset(pkt.dest_mac+5, (arp_hdr->sender_ha[5]&0xFF), (sizeof(byte1)));
	
		*((byte4 *) &(pkt.sender_ip)) = *((byte4 *) &(arp_hdr->target_pa));
		*((byte4 *) &(pkt.target_ip)) = *((byte4 *) &(arp_hdr->sender_pa));

	
		for (i = 0;i<6;i++)
		{
			pkt.target_mac[i]=pkt.dest_mac[i];
		}
	
	 	if ( sendto( sock, &pkt,sizeof(pkt), 0, (struct sockaddr *)&sa,sizeof(sa) ) < 0 )
	 	{
	   		perror("sendto");
			exit(-1);
	  	}
	  	
		if (DEBUG)
			debug(pkt);
		
		/*************************Finish packet procesing****************************/

	}
	free(buffer);
	close(sock);
}	

