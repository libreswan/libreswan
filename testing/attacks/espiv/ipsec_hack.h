#include <stdio.h>              /* printf */
#include <string.h>             /* strncpy */
#include <unistd.h>             /* close */
#include <signal.h>
#include <arpa/inet.h>          /* inet_ntoa */
#include <sys/socket.h>         /* socket */
#include <linux/if_ether.h>     /* ETH_P_IP, struct ethhdr */
#include <linux/if.h>           /* IFNAMSIZ, IFF_PROMISC, struct ethreq */
#include <linux/udp.h>
#include <netinet/ip.h>         /* struct iphdr */
#include <sys/ioctl.h>          /* ioctl */
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <time.h>

#define BUFSIZE 1540

#define u32 unsigned int
#define u16 unsigned short
#define u8 unsigned char

typedef struct {
	u32 spi;
	u32 SequenceNumber;
	u8 iv[8];               /* iv 32bit/64bit */
	u8 payloaddata[1];      /* payload data, length variable */
} EspHeader;

typedef struct {
	u8 nextheader;
	u8 length; /* length of authentication data field */
	u16 RESERVED;
	u32 spi;
	u32 SequenceNumber;
	u8 authenticationdata[1]; /* variable length */
} AhHeader;

typedef struct {
	u16 SourcePort;
	u16 DestinationPort;
	u16 TotaLength;
	u16 CheckSum;
} UdpHeader;

typedef struct {
	u32 src_address;
	u32 fake_src_address;
	u32 fake_dst_address;
	u32 dst_address;
	u32 spi;
	u32 last_length;
	u8 smac[6];
	u8 dmac[6];
	char listen_if[10];
	char send_if[10];
	u32 seq;
	u8 verbose;
	u8 spi_change_detection;
	u32 packet_print_intervall;
	time_t spi_last_seen;
	time_t start_time;
	u32 spi_wait_time;
	enum { init, wait, send_done } state;
	u8 guess[8];
	u8 block_to_crack[8];
	u8 original_iv[8];
	u8 last_iv[8];
	u32 ap_len;
	u32 ap_overhead;
	u32 packet_counter;
	u32 guess_counter;
	u32 gw;
	u8 rsv_bit;
} option_data;

int read_hex_int(char *c);
u8 read_nyble(FILE *fp, int *err);
u8 read_byte(u8 *c, u8 endmark);
void read_mac(u8 *c, u8 *mac);
void read_block(u8 *c, u8 *block);
u32 read_dotted_ipv4_address(u8 *str);
u16 ipheader_checksum(u16 *buffer, u16 len);
void ipv4_print_address(u32 address);
int read_arguments(int argc, char *argv[], option_data *opt);
u16 compute_tcpudp_checksum(u32 sourceip,
			    u32 destip,
			    u8 protocol,
			    u16 datalen,
			    u8 *data);
