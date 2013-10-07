#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

#include "headers.h"

#define TCPDUMP_MAGIC		0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

#if BYTE_ORDER == BIG_ENDIAN
#define ETHER_TYPE_IP	0x0008
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
#define ETHER_TYPE_IP	0x0800
#endif
#define IP_TYPE_TCP	0x06
#define IP_TYPE_UDP	0x11

static long limit_pktcnt = -1;
static long limit_filesize = -1;
static long limit_seconds = -1;
static long var_pktcnt = 0;
static long var_filesize = 0;
static long var_seconds = 0;
static time_t t_start, t_now;

static void
print_usage(const char* pro_name)
{
	printf("This program aims to dump the traffic with HTTP headers,\n");
	printf("i.e., the payload of HTTP is dropped if unencripted content\n");
	printf("carried, otherwise, only TCP header is recorded.\n\n");
	printf("Usage: %s [-h] [-c count] [-C file_size]\n", pro_name);
	printf("[-g duration] [-i interface | -r file] [-w file]\n\n");
	printf("Most of these options are consistent with TCPDUMP.\n");
}

static int
if_go_on(void){
	time(&t_now);
	var_seconds = (int)t_now-t_start;
	if(limit_pktcnt != -1 && var_pktcnt>=limit_pktcnt){
		return -1;
	}else if(limit_seconds != -1 && var_seconds>=limit_seconds){
		return -1;
	}else{
		return 0;
	}
}

static void
nprint(const char* data, int dl){
	char *tmem = malloc(sizeof(char)*(dl+1));
	memset(tmem, '\0', dl+1);
	memcpy(tmem, data, dl);
	printf("%s", tmem);
}

static int
is_http_message(const char *data, unsigned long dl){
	char *HTTP_SIGNATURE_ARRAY[] = {
	"HTTP/1.1", "HTTP/1.0", "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE",
    "TRACE", "CONNECT", "PATCH", "LINK", "UNLINK", "PROPFIND", "MKCOL", "COPY",
    "MOVE", "LOCK", "UNLOCK", "POLL", "BCOPY", "BMOVE", "SEARCH", "BDELETE",
    "PROPPATCH", "BPROPFIND", "BPROPPATCH", "LABEL", "MERGE", "REPORT","UPDATE",
	"CHECKIN", "CHECKOUT", "UNCHECKOUT", "MKACTIVITY", "MKWORKSPACE",
	"VERSION-CONTROL", "BASELINE-CONTROL", "NOTIFY", "SUBSCRIBE", "UNSUBSCRIBE","ICY",
	};
	
	int flag = 0;
	/* From RFC 2774 - An HTTP Extension Framework
     * Support the command prefix that identifies the presence of
     * a "mandatory" header.
     */
	if (dl >= 2){
        if (strncmp(data, "M-", 2)==0 || strncmp(data,"\r\n",2)==0){
            data += 2;
			dl -= 2;
        }
    }
	if (dl >= 17){
		// Look for the space following the Method
		int index=0;
		char *ptr = data;
		while(index <= 17) {
	        if (*ptr == ' ')
	            break;
	        else {
	            ptr++;
	            index++;
	        }
	    }
		//printf("**%d\n", index);
		// Check the SIGNATURES that have same length
	    switch (index) {
	    case 3:
	        if (strncmp(data, "GET", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "PUT", index) == 0) {
	            flag=1;
	        }
			else if (strncmp(data, "ICY", index) == 0) {
	            flag=1;
	        }
			break;
	    case 4:
	        if (strncmp(data, "COPY", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "HEAD", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "LOCK", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "MOVE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "POLL", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "POST", index) == 0) {
	            flag=1;
	        }
	        break;

	    case 5:
	        if (strncmp(data, "BCOPY", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "BMOVE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "MKCOL", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "TRACE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "LABEL", index) == 0) {  /* RFC 3253 8.2 */
	            flag=1;
	        }
	        else if (strncmp(data, "MERGE", index) == 0) {  /* RFC 3253 11.2 */
	            flag=1;
	        }
	        break;

	    case 6:
	        if (strncmp(data, "DELETE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "SEARCH", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "UNLOCK", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "REPORT", index) == 0) {  /* RFC 3253 3.6 */
	            flag=1;
	        }
	        else if (strncmp(data, "UPDATE", index) == 0) {  /* RFC 3253 7.1 */
	            flag=1;
	        }
	        else if (strncmp(data, "NOTIFY", index) == 0) {
	            flag=1;
	        }
	        break;

	    case 7:
	        if (strncmp(data, "BDELETE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "CONNECT", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "OPTIONS", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "CHECKIN", index) == 0) {  /* RFC 3253 4.4, 9.4 */
	            flag=1;
	        }
	        break;

	    case 8:
			if (strncmp(data, "HTTP/1.1", index) == 0) {
	            flag=1;
	        }
			else if (strncmp(data, "HTTP/1.0", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "PROPFIND", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "CHECKOUT", index) == 0) { /* RFC 3253 4.3, 9.3 */
	            flag=1;
	        }
	        else if (strncmp(data, "CCM_POST", index) == 0) {
	            flag=1;
	        }
			break;
	    case 9:
	        if (strncmp(data, "SUBSCRIBE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "PROPPATCH", index) == 0) {
	            flag=1;
	        }
	        else  if (strncmp(data, "BPROPFIND", index) == 0) {
	            flag=1;
	        }
	        break;

	    case 10:
	        if (strncmp(data, "BPROPPATCH", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "UNCHECKOUT", index) == 0) {  /* RFC 3253 4.5 */
	            flag=1;
	        }
	        else if (strncmp(data, "MKACTIVITY", index) == 0) {  /* RFC 3253 13.5 */
	            flag=1;
	        }
	        break;

	    case 11:
	        if (strncmp(data, "MKWORKSPACE", index) == 0) {  /* RFC 3253 6.3 */
	            flag=1;
	        }
	        else if (strncmp(data, "UNSUBSCRIBE", index) == 0) {
	            flag=1;
	        }
	        else if (strncmp(data, "RPC_CONNECT", index) == 0) {
	            flag=1;
	        }
	        break;

	    case 15:
	        if (strncmp(data, "VERSION-CONTROL", index) == 0) {  /* RFC 3253 3.5 */
	            flag=1;
	        }
	        break;

	    case 16:
	        if (strncmp(data, "BASELINE-CONTROL", index) == 0) {  /* RFC 3253 12.6 */
	            flag=1;
	        }
	        break;

	    default:
	        break;
	    }
	}
	return flag;
}

static char* 
http_header_end(const char *header, unsigned long len)
{
    const char *lf, *nxtlf, *end;
    const char *buf_end;
   
    end = NULL;
    buf_end = header + len;
	lf =  memchr(header, '\n', len);
    if (NULL == lf){
        return NULL;
	}
    lf++; /* next charater */
    nxtlf = memchr(lf, '\n', buf_end - lf);
    while (nxtlf != NULL) {
		end = nxtlf;	// Drop the truncated data
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', buf_end - nxtlf);
    }

    return (char *)end;
}

static char*
truncate_packet(const struct pcap_pkthdr *pkthdr, const char *raw_data){
	char *tp=NULL, *ipend=NULL;
	ethhdr_t*	ethh = NULL;
	iphdr_t*	iph = NULL;
	tcphdr_t*	tcph = NULL;
	udphdr_t*	udph = NULL;
	httphdr_t*	httph = NULL;
	int iphl=-1, ipttl=-1;
	int tcphl=-1, tcpdl=-1;
	int httphl=-1;
	
	ethh=(ethhdr_t*)raw_data;
	if(ETHER_TYPE_IP != ntohs(ethh->ether_type)){
		return NULL;
	}
	iph=(char*)ethh+sizeof(ethhdr_t);
	iphl=(iph->ihl<<2);			// IP header length
	ipttl=ntohs(iph->tot_len);	// IP total length: header + data
	if(IP_TYPE_TCP == iph->protocol){
		// Store packets up to TCP header
		tcph=(char*)iph+iphl;
		tcphl=(tcph->th_off<<2);	// TCP header length
		tcpdl=ipttl-iphl-tcphl;		// TCP data length
		httph=(char*)tcph+tcphl;
		int flag = is_http_message((char*)httph, tcpdl);
	    if(0 == flag){	// not http
			return (char*)tcph+tcphl-1;
		}else{
			// Store packets up to HTTP header
			return http_header_end((char*)httph, tcpdl);
		}
	}else if(IP_TYPE_UDP == iph->protocol){
		// Store packets up to UDP header
		udph=(char*)iph+iphl;
		return (char*)udph+sizeof(udphdr_t)-1;
	}else{
		// For other protocols out of TCP and UDP, store entire packets.
		return (char*)raw_data+pkthdr->caplen-1;
	}
}

int
main(int argc, char *argv[]){
	char* interface = NULL;
	char* tracefile = NULL;
	char* dumpfile = NULL;
	// Parse options
	int opt;
	const char *optstr = "c:C:g:i:r:w:h";
	while((opt = getopt(argc, argv, optstr)) != -1){
		switch(opt){
			case 'h':
				print_usage(argv[0]);
				return 0;
			case 'c':
				limit_pktcnt = atoi(optarg);
				break;
			case 'C':
				limit_filesize = atoi(optarg);
				break;
			case 'g':
				limit_seconds = atoi(optarg);
				break;
			case 'i':
				interface = optarg;
				break;
			case 'r':
				tracefile = optarg;
				break;
			case 'w':
				dumpfile = optarg;
				break;
			default:
				print_usage(argv[0]);
				return 0;
		}
	}
	
	if (interface == NULL && tracefile == NULL){
		print_usage(argv[0]);
		exit(-1);
	}
	
	// Processing traffic
	time(&t_start);

	char errbuf[PCAP_ERRBUF_SIZE];
	char *raw, *data_end;
	pcap_t *cap;
	pcap_dumper_t *dumper;
	struct pcap_pkthdr *pkthdr;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	
	if (tracefile != NULL){
		// work with offline file
		cap = pcap_open_offline(tracefile, errbuf);
	}else if(interface != NULL){
		// work with interface
		cap = pcap_open_live(interface, 65535, 0, 1000, errbuf);
	}
	if( cap == NULL){
		printf("%s\n",errbuf); exit(-1);
	}
	
	FILE* f;
	char fname[128];
	int file_cnt = 0;
	dumper = NULL;
	if(NULL != dumpfile){
		strcpy(fname, dumpfile);
		dumper = pcap_dump_open(cap, fname);
		f = pcap_dump_file(dumper);
	}else{
		strcpy(fname, "standard output");
		f = stdout;
	}
	file_cnt++;
	
	int res;
	while(0 == if_go_on()){
		res = pcap_next_ex(cap, &pkthdr, &raw);
		if( -1 == res || 0 == res){
			printf("Do not worry, I'm trying to catch data...\n");
			continue;
		} else if(-2 == res){
			printf("No more packets.\n");
			break;
		} else{
			// without problems
			data_end = truncate_packet(pkthdr, raw);
			if( NULL == data_end ) {continue;}

			var_pktcnt++;
			pkthdr->caplen = data_end - raw + 1;
			
			// Store the data between (raw) and (data_end) pointers
			if(f==stdout){
				printf("stdout: pkt %d --> caplen %d, len %d\n", var_pktcnt, pkthdr->caplen, pkthdr->len);
			}else{
				var_filesize += pkthdr->caplen;
				// dump the data
				if (limit_filesize == -1 || var_filesize <= limit_filesize){
					pcap_dump(f, pkthdr, raw);
				}else{
					pcap_dump_flush(dumper);
					pcap_dump_close(dumper);
					sprintf(fname, "%s.%d", dumpfile, ++file_cnt);
					dumper = pcap_dump_open(cap, fname);
					f = pcap_dump_file(dumper);
					pcap_dump(f, pkthdr, raw);
					var_filesize = pkthdr->caplen;
				}
			}
		}	
	}
	
	if(dumper != NULL){
		pcap_dump_flush(dumper);
		pcap_dump_close(dumper);
	}
	
	printf("%d packets captured, time elapsed %d seconds\n", 
			var_pktcnt, var_seconds);
	return 0;
}