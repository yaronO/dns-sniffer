#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define BUFSIZE 65536
#define A 1
#define AAAA 28
#define CNAME 5
#define A_LENGTH 4 
#define AAAA_LENGTH 16

#define DNS_PORT 53

// DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

// Answer field in DNS 
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Save current alignment and set new to 1-byte
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop) // Restore

 
int DnsHandle(unsigned char *); 
int ReadDomainFromQuestion(unsigned char *, unsigned char **); 
int ReadDnsAnswers(unsigned char *, struct DNS_HEADER *, struct RES_RECORD *, unsigned char *); 
int ReadRdata(unsigned char *, struct RES_RECORD *);
void PrintResults(int, struct RES_RECORD answers[], unsigned char **); 
unsigned char* ReadName(unsigned char *, unsigned char *, int *);
void CleanUp(struct RES_RECORD *, int);
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main() {
    pcap_t *handle;
    pcap_if_t *alldevsp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    struct bpf_program filter;
    char filter_exp[] = "udp src port 53";  // Only DNS responses
    bpf_u_int32 subnet_mask, ip;
    
    //Find all device to listen to 
    if( pcap_findalldevs( &alldevsp , errbuf) )
    {
        printf("Error finding devices : %s" , errbuf);
        return 1;
    }

    // The first result of device list is the default according to libpcap man
    device = alldevsp->name;

    // Get network address and subnet mask
    if (pcap_lookupnet(device, &ip, &subnet_mask, errbuf) == -1) 
    {
        fprintf(stderr, "Error getting network address: %s\n", errbuf);
        ip = 0;
        subnet_mask = 0;
    }

    // Open device for live capture
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) 
    {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return 1;
    }

    // Make sure we're capturing on an Ethernet device
    if (pcap_datalink(handle) != DLT_EN10MB) 
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
        pcap_close(handle);
        return 1;
    }

    // Compile the filter expression
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) 
    {
        fprintf(stderr, "Error compiling filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    // Apply the filter
    if (pcap_setfilter(handle, &filter) == -1) 
    {
        fprintf(stderr, "Error setting filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(&filter);
        pcap_close(handle);
        return 1;
    }

    // Start packet capture loop
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_freecode(&filter);
    pcap_close(handle);
    return 0;
}

// libpcap packet handler
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct iphdr *ip_header;
    struct udphdr *udp_header;
    unsigned char *dns_data;
    int res = 0;
    
    // Skip Ethernet header (14 bytes)
    const u_char *ip_packet = packet + ETH_HLEN;
    
    // Get IP header
    ip_header = (struct iphdr*)ip_packet;
    
    // Verify it's UDP
    if (ip_header->protocol != IPPROTO_UDP) 
    {
        return;
    }

    //ip_header->ihl gives header length in how many 32-bit words are in header. Multiply by 4 to get bytes.( 5 = 32*5 = 20B)    
    int ip_header_len = ip_header->ihl * 4;
    
    // Get UDP header
    udp_header = (struct udphdr*)(ip_packet + ip_header_len);
    
    // Verify it's from port 53 (DNS)
    if (ntohs(udp_header->source) != DNS_PORT) 
    {
        return;
    }
    // Get DNS data
    dns_data = (unsigned char*)(ip_packet + ip_header_len + sizeof(struct udphdr));
    
   // forwared DNS packet to handle result 
    res = DnsHandle(dns_data);
    if (res == -1)
    {
        return; 
    }
}

//Function handle the DNS packet 
int DnsHandle(unsigned char *dns_data)
{

    struct DNS_HEADER *dns_header;    
    struct RES_RECORD answers[20]; //the replies from the DNS server
    unsigned char *reader; // pointer that run over dns ANSWER record
    unsigned char *domain_name;
    int res = 0;
    
    dns_header = (struct DNS_HEADER*)dns_data;

    // Verify it's a DNS response (QR bit set)
    if (dns_header->qr != 1) 
    {
        return -1;
    }

    //Read the the domain name from Question QNAME
    res = ReadDomainFromQuestion(dns_data,&domain_name);
    if (res == -1)
    {
        return -1;
    }
    reader = dns_data + sizeof(struct DNS_HEADER) + sizeof(struct QUESTION) + strlen(domain_name) +1; // move ahead of dns header and qname(domain name)
    
    //Work on the DNS answer record to parse ip's
    res = ReadDnsAnswers(reader,dns_header,answers,dns_data);
    if (res == -1)
    {
        free(domain_name);
        return -1;
    }
       
    //Print all results ,and clean memory 
    PrintResults(ntohs(dns_header->ans_count),answers,&domain_name); 

    return 0;
}

//Extract the Domain name
int ReadDomainFromQuestion( unsigned char *dns_data, unsigned char **domain_name)
{ 
    unsigned char *qname,*reader;
    int offset =0;

    qname = dns_data + sizeof(struct DNS_HEADER); // qname point to QNAME in QUESTION record
    reader = qname; // specific for domain name reader and qname point to same location
    *domain_name = ReadName(reader,qname,&offset); // read the name of the domain
    if (*domain_name == NULL)
        return -1;

    return 0; 
}

//Function that extract IP's, and save to array for forther use
int ReadDnsAnswers(unsigned char *reader, struct DNS_HEADER *dns, struct RES_RECORD *answers, unsigned char *dns_start)
{
    int offset=0;
    int i,j;
    int res =0;
    
    //Run over all ANSWERS RECORDS in response message and for each one parse the  NAME and RDATA
    //ntohs - function converts the unsigned short integer netshort from network byte order to host byte order
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,dns_start,&offset); // read NAME in ANSWER record
        if (answers[i].name == NULL)
        {
            CleanUp(answers,i);
            return 1;
        }
        reader = reader + offset; // move ahead of NAME
        answers[i].resource = (struct R_DATA*)(reader); // parse information data from ANSWER record
        reader = reader + sizeof(struct R_DATA); // point to the start of RDATA

        // Check TYPE and validate length, Each TYPE parse the RDATA and move reader pointer to next DNS ANSWER record
        if ((ntohs(answers[i].resource->type) == A) && (ntohs(answers[i].resource->data_len) == A_LENGTH ))
        {
            res = ReadRdata(reader, &answers[i]);
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else if ((ntohs(answers[i].resource->type) == AAAA) && (ntohs(answers[i].resource->data_len) == AAAA_LENGTH ))
        {
            res = ReadRdata(reader, &answers[i]);
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else if (ntohs(answers[i].resource->type) == CNAME)
        {
            answers[i].rdata = ReadName(reader,dns_start,&offset);
            reader = reader + offset;
        }

        //Check allocation faiure during rdata allocation
        if (res == 1)
        {
            free(answers[i].name);
            CleanUp(answers,i);
            return 1;
        }

    }
}

//Read RDATA from ANSWER record and save it in answer for forther use
int ReadRdata(unsigned char *reader , struct RES_RECORD *answer)
{
    int j;

    answer->rdata = (unsigned char*)malloc(ntohs(answer->resource->data_len)); // size may vary so allocate memory
    
    if (answer->rdata == NULL)
    {
        return -1;
    }
    // Assign IP as raw data 
    for(j=0 ; j<ntohs(answer->resource->data_len) ; j++){
        answer->rdata[j]=reader[j];
    }

    return 0;
}

//Print out results
void PrintResults(int ans_count, struct RES_RECORD *answers, unsigned char **domain_name)
{
    int i;

    printf("Domain : %s\n",*domain_name);

    //For each answer parse relevant ip to readable format, print the ip , free memory after use
    //inet_ntoa - convert converts the Internet host address in, given in network byte order, to a string in IPv4 dotted-decimal notation
    //inet_ntop -This function converts the network address structure src in the af address family into a character string
    for(i=0 ; i < ans_count ; i++)
    {
        switch(ntohs(answers[i].resource->type)){
            case A:
                long *p;
                struct sockaddr_in a;
                p=(long*)answers[i].rdata;
                a.sin_addr.s_addr=(*p); //working without ntohl
                printf("IPv4 : %s\n",inet_ntoa(a.sin_addr));
                free(answers[i].name);
                free(answers[i].rdata);
                break;

            case AAAA:
                char ipv6[INET6_ADDRSTRLEN]; // 16B
                inet_ntop(AF_INET6, answers[i].rdata, ipv6, INET6_ADDRSTRLEN);
                printf("IPv6: %s\n", ipv6);
                free(answers[i].name);
                free(answers[i].rdata);
                break;

            case CNAME:
                //printf("CNAME : %s",answers[i].rdata);
                free(answers[i].name);
                free(answers[i].rdata); 
                break;
        
        }
    }
    
    free(*domain_name); // free domain name memory from ReadNane
}

//Read NAME QNAME CNAME etc..., hande packets with reduction scheme
unsigned char* ReadName(unsigned char *reader, unsigned char *dns_start, int *rel_offset)
{
    unsigned char *name; //store the name 
    unsigned int p=0; //two uses, p index and present the characters until the dot 3www8somthing3com, p=3=www, p=8=somthing and so on..
    unsigned int jumped=0; // jump to different memory area 0=no, 1 yes
    unsigned int abs_offset;// the absolute offset from base DNS
    int i,j;
 
    *rel_offset = 1; // relative offset from reader
    
    name = (unsigned char*)malloc(256); // name may vary so allocate memory
    
    if(name == NULL)
        return NULL;
 
    name[0]='\0';
 
    //Read the names in 3www6google3com format
    while(*reader!=0)
    {
        // Labels are places any ware in the DNS packet so each Octet should be check
        // Check if two first bits are one's (bigger number then 0xC0 must include two one's)
        if(*reader>=0xC0)
        {
            // every Pointer to lable takes two Octet (16b) 
            abs_offset = (( *reader & 0x3F) << 8) + *(reader + 1); // add first octet without first 11, and add the next octet
            reader = dns_start + abs_offset - 1; // point to actual name in DNS packet
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1; // advance 
 
        if(jumped==0)
        {
            *rel_offset = *rel_offset + 1; //if we haven't jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *rel_offset = *rel_offset + 1; //number of steps we actually moved forward in the packet (2 Octes)
    }
 
    //now convert 3www8somthing3com to www.somthing.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        // p = # character's to the dot(.)
        p=name[i];
        
        // Copy character's
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

//Clean up function if error occur
void CleanUp(struct RES_RECORD *answers, int num_to_clean)
{
    int i;

    for (i = num_to_clean -1; i >= 0; i--)
    {
        free(answers[i].name);
        free(answers[i].rdata);
    }

}
