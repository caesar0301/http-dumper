#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <sys/types.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN	0
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN	1
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER (*(u_int16_t *)"\0\xff" < 0x100)
#endif

/* Ethernet header structure */
typedef struct ethernet_header ethhdr_t;
struct ethernet_header
{
  u_int8_t  ether_dhost[6];		/* Destination addr	*/
  u_int8_t  ether_shost[6];		/* Source addr */
  u_int16_t ether_type;			/* Packet type */
};

/* IP header structure */
typedef struct ip_header iphdr_t;
struct ip_header
{
#if BYTE_ORDER == BIG_ENDIAN
	u_int8_t version:4;
    u_int8_t ihl:4;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	u_int8_t ihl:4;
    u_int8_t version:4;
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
#define	IP_RF 0x8000			/* Reserved fragment flag */
#define	IP_DF 0x4000			/* Dont fragment flag */
#define	IP_MF 0x2000			/* More fragments flag */
#define	IP_OFFMASK 0x1fff		/* Mask for fragmenting bits */
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
};

/* TCP header structure */
typedef struct tcp_header tcphdr_t;
struct tcp_header
{
    u_int16_t th_sport;		/* Source port */
    u_int16_t th_dport;		/* Destination port */
    u_int32_t th_seq;		/* Sequence number */
    u_int32_t th_ack;		/* Acknowledgement number */
#if BYTE_ORDER == BIG_ENDIAN
	u_int8_t th_off:4;		/* (Unused) */
    u_int8_t th_x2:4;		/* Data offset */
#else
	u_int8_t th_x2:4;
    u_int8_t th_off:4;
#endif
    u_int8_t th_flags;
#  define TH_FIN	0x01
#  define TH_SYN	0x02
#  define TH_RST	0x04
#  define TH_PUSH	0x08
#  define TH_ACK	0x10
#  define TH_URG	0x20
    u_int16_t th_win;		/* Window */
    u_int16_t th_sum;		/* Checksum */
    u_int16_t th_urp;		/* Urgent pointer */
};

typedef struct udp_header udphdr_t;
struct udp_header{
	u_int16_t uh_sport;               /* source port */
	u_int16_t uh_dport;               /* destination port */
	u_int16_t uh_ulen;                /* udp length */
	u_int16_t uh_sum;
};

typedef struct http_header httphdr_t;
struct http_header{
	char	*startchr;
	char	*endchr;
};

#endif