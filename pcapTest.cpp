#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>
#include <queue>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

struct Event
{
	uint16_t TcpPortS;
	uint16_t TcpPortD;
	uint32_t IpAddressS;
	uint32_t IpAddressD;
	uint32_t PacketNumber;
};
std::vector<Event> events;
Event currentEvent={};
uint32_t currentPacketNumber;

int TESTEventToVector()
{

	events.push_back(currentEvent);
	//printEvents(events);
	currentEvent={};
	//currentEvent={5,6,7,8};
	currentEvent.IpAddressS=100;
	events.push_back(currentEvent);
	//printEvents(events);

}


int printSflowFS_RP_HS_IPV4_TCP(const u_char * fs_TCP_Packet)
{
	printf(KRED "\n\t\t\t\t\t\t###TCP Record");
	auto sFS_RP_HS_IPV4_TCP_SourcePort =__bswap_16(*reinterpret_cast<uint16_t const*>(fs_TCP_Packet));
	auto sFS_RP_HS_IPV4_TCP_DestinationPort =__bswap_16(*reinterpret_cast<uint16_t const*>(fs_TCP_Packet+2));
	
	printf("\n"
		"\t\t\t\t\t\tTCPs:\t\t%d\n"
		"\t\t\t\t\t\tTCPd:\t\t%d\n"
		,sFS_RP_HS_IPV4_TCP_SourcePort	
		,sFS_RP_HS_IPV4_TCP_DestinationPort	
	);
		currentEvent.TcpPortS=sFS_RP_HS_IPV4_TCP_SourcePort;
		currentEvent.TcpPortD=sFS_RP_HS_IPV4_TCP_DestinationPort;
	printf("\n"
		"\t\t\t\t\t\tsFS_RP_HS_IPV4_TCP_SourcePort:\t\t%02x\n"
		"\t\t\t\t\t\tsFS_RP_HS_IPV4_TCP_DestinationPort:\t%02x\n"
		,sFS_RP_HS_IPV4_TCP_SourcePort	
		,sFS_RP_HS_IPV4_TCP_DestinationPort	
	);	

	printf("\n\t\t\t\t\t\t###TCP Record END\n" KWHT);

}
int printSflowFS_RP_HS_IPV4(const u_char * fs_IPV4_Packet)
{
	printf(KBLU "\n\t\t\t\t\t###IPV4 Record");
	auto sFS_RP_HS_IPV4_Protocol=*reinterpret_cast<unsigned char const*>(fs_IPV4_Packet+9);
	auto sFS_RP_HS_IPV4_Source=reinterpret_cast<uint32_t const*>(fs_IPV4_Packet+12);
	auto sFS_RP_HS_IPV4_Destination=reinterpret_cast<uint32_t const*>(fs_IPV4_Packet+16);


	//PRINT IPs
	struct in_addr ipS,ipD;
	ipS.s_addr=*sFS_RP_HS_IPV4_Source;
	ipD.s_addr=*sFS_RP_HS_IPV4_Destination;
	printf("\n"
		"\t\t\t\t\tips:\t%s\n"
		"\t\t\t\t\tipD:\t%s\n"
		,inet_ntoa(ipS)
		,inet_ntoa(ipD)
	);
	currentEvent.IpAddressS=*sFS_RP_HS_IPV4_Source;
	currentEvent.IpAddressD=*sFS_RP_HS_IPV4_Destination;
	//
	printf("\n"
		"\t\t\t\t\tsFS_RP_HS_IPV4_Source:\t\t%02x\n"
		"\t\t\t\t\tsFS_RP_HS_IPV4_Protocol:\t%02x\n"
		,*sFS_RP_HS_IPV4_Source
		,sFS_RP_HS_IPV4_Protocol
	);
	//Check if TCP 
	if(sFS_RP_HS_IPV4_Protocol==0x06)
	{
		printSflowFS_RP_HS_IPV4_TCP(fs_IPV4_Packet+20);
	}
	else
	{
		printf("Not implemented FS->RP->HS->IPV4 Protocol");
	}
	printf(KBLU "\n\t\t\t\t\t###IPV4 Record END\n\n" KWHT);
}
int printSflowFlowSampleHeaderOfSampledPacketEthernet(const u_char * fs_HS_Packet)
{
	printf(KMAG "\n\t\t\t\t###Ethernet Record");
	auto sFS_RP_HS_Type=__bswap_16(*reinterpret_cast<uint16_t const*>(fs_HS_Packet+12));
	printf("\n"
		"\t\t\t\tsFS_RP_HS_Type:\t%02x\n"
		,sFS_RP_HS_Type		
	);
	//Check if IPV4
	if(sFS_RP_HS_Type==0X0800)
	{
		printSflowFS_RP_HS_IPV4(fs_HS_Packet+14);
	}
	else
	{
		printf("Not implemented..FS->RP->HS->Type\n");
	}
	printf(KMAG "\t\t\t\t###Ethernet Record END\n\n" KWHT);
}
int printSflowFlowSample(const u_char * fsPacket)
{
	auto sFS_FlowRecord=__bswap_32(*reinterpret_cast<uint32_t const*>(fsPacket+28));
	printf("\n"
		"\t\tsFS_FlowRecord:\t%02x\n"
		,sFS_FlowRecord		
	);
	const u_char *fsRawPacket=fsPacket+32;
	for(int i=0;i<sFS_FlowRecord;i++)
	{
		//
		printf(KCYN "\n\t\t\t###Flow Record:%d",i+1);
		
		auto sFS_FR_PacketHeaderV= __bswap_32(*reinterpret_cast<uint32_t const*>(fsRawPacket));
		auto sFS_FR_FormatV=sFS_FR_PacketHeaderV & 0X00000FFF;
		auto sFS_FR_FlowDataLength=__bswap_32(*reinterpret_cast<uint32_t const*>(fsRawPacket+4));
		if(sFS_FR_FormatV==1)
		{
			//###RAW PACKET HEADER:RP
			
			auto sFS_FR_RP_HeaderProtocol=__bswap_32(*reinterpret_cast<uint32_t const*>(fsRawPacket+8));
			auto sFS_FR_RP_OriginalPacketLength=__bswap_32(*reinterpret_cast<uint32_t const*>(fsRawPacket+20));
			printf("\n"
				"\t\t\tsFS_RP_FormatV:\t\t\t%02x\n"
				"\t\t\tsFS_RP_FlowDataLength:\t\t%02x\n"
				"\t\t\tsFS_RP_OriginalPacketLength:\t%02x\n"
				"\t\t\tsFS_RP_HeaderProtocol:\t\t%02x\n"
				,sFS_FR_FormatV
				,sFS_FR_FlowDataLength
				,sFS_FR_RP_OriginalPacketLength
				,sFS_FR_RP_HeaderProtocol		
			);
			if(sFS_FR_RP_HeaderProtocol==1)
			{
				currentEvent={};
				currentEvent.PacketNumber=currentPacketNumber;
				printSflowFlowSampleHeaderOfSampledPacketEthernet(fsRawPacket+24);
				events.push_back(currentEvent);
			}
			else
			{
				printf("Not implemented..FS->FR->HeaderProtocol\n");
			}
		}
		else
		{
			printf("Not implemented..FS->RP->Format\n");
		}
		
		fsRawPacket=fsRawPacket+sFS_FR_FlowDataLength+8;
		printf(KCYN "\t\t\t###Flow Record:%d END###\n" KWHT,i+1);

	}
}
int printSFlowDatagram(const u_char * sPacketP)
{
	auto sDatagramVersionV=*reinterpret_cast<uint32_t const*>(sPacketP);

	auto sAddressTypeV=*reinterpret_cast<uint32_t const*>(sPacketP+4);

	const u_char *sSubAgentIdP;
	//IPV4 ? V6
	if(__bswap_32(sAddressTypeV)==1)
	{
		auto sAddressTypeV=*reinterpret_cast<uint32_t const*>(sPacketP+8);
		sSubAgentIdP=sPacketP+12;
	}
	else if(sAddressTypeV==1)
	{
		auto sAddresTypeV=*reinterpret_cast<uint64_t const*>(sPacketP+8);
		sSubAgentIdP=sPacketP+24;
	}
	else
	{
		printf("Sflow Ip Header Problem..\n");
		return 1;
	}
	auto sSubAgentIdV=*reinterpret_cast<uint32_t const*>(sSubAgentIdP);
	//----OTHER HEADER FIELDS
	//----HERE
	
	//
	//sSubAgentIdP is the new Packet Pointer
	auto sNumSamplesP=sSubAgentIdP+12;
	auto sNumSamplesV=__bswap_32(*reinterpret_cast<uint32_t const*>(sNumSamplesP));

	printf("\n--\n"
	"sDatagramVersionV:\t%02x\n"
	"sAddressTypeV:\t\t%02x\n"
	"sSubAgentIdV:\t\t%02X\n"
	"sNumSamplesV:\t\t%02X\n"
	"\n"
	,sDatagramVersionV
	,sAddressTypeV
	,sSubAgentIdV
	,sNumSamplesV		
	);
	
	//READ SFLOW SAMPLES
	auto sFlowP=sSubAgentIdP+16;
	for(int i=0;i<sNumSamplesV;i++)
	{
		printf(KGRN "\n\t###Flow Sample:%d\n",i+1);
		auto sFlowSampleHeaderV= __bswap_32(*reinterpret_cast<uint32_t const*>(sFlowP));
		auto sFlowSampleTypeV=sFlowSampleHeaderV & 0X00000FFF;
		auto sFlowSampleLength=__bswap_32(*reinterpret_cast<uint32_t const*>(sFlowP+4));
		
		printf("\n"
		"\tsFlowSampleTypeV:\t%02x\n"
		"\tsFlowSampleLength:\t%02x\n"
		,sFlowSampleTypeV
		,sFlowSampleLength
		);

		//enterprise=0,format=1
		if(sFlowSampleTypeV==1)
		{
			//READ FLOW Sample
			printSflowFlowSample(sFlowP+8);
		}
		else{
			printf("Counter Samples are not implemented");
		}
		//NEXT Sflow PACKET
		sFlowP=(sFlowP+8+sFlowSampleLength);
		printf(KGRN "\n\t###Flow Sample:%d END###\n" KWHT,i+1);
	}
}
int printEvents(std::vector<Event> &list)
{
	int i=0;	
	for(std::vector<Event>::iterator it=list.begin(); it!=list.end();++it)
	{
		struct in_addr ipS,ipD;
		ipS.s_addr=it->IpAddressS;
		ipD.s_addr=it->IpAddressD;

		printf("\n###PACKET:%d Event:%d####\n"
			"TcpPortS:%d\n"
			"TcpPortP:%d\n"
			"IdAddressS:%s\n"
			"IdAddressP:%s\n"
			"\n"
			,it->PacketNumber
			,++i
			,it->TcpPortS
			,it->TcpPortD
			,inet_ntoa(ipS)
			,inet_ntoa(ipD)
		);
	}
}
void hexDump (const char *desc,const void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
	if((i % 8) == 0 && i!=0)
		printf(" ");
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

int main2(int argc, char *argv[])
{


	if(argc != 2)
	{	
		printf("File input expected%d",argc);
		exit(1);
	}

	//get file
	char *filename = argv[1];
	std::cout<<"Processing File::"<<filename<<std::endl;
	//error buffer
	char errbuff[PCAP_ERRBUF_SIZE];

	//open file and create pcap handler
	pcap_t * handler = pcap_open_offline(filename, errbuff);
	if(handler == NULL)
	{
		printf("File error...");
		exit(1);
	}
	//The header that pcap gives us
	struct pcap_pkthdr *header;

	//The actual packet 
	const u_char *packet;   

	//write to file 
	//FILE *fp = fopen ( "pcapTestResult.txt", "w" ) ;

	u_int size_ip;
	u_int size_tcp;
	int i=0;
	while (pcap_next_ex(handler, &header, &packet) >= 0)
	{
		//READ PCAP PACKETS
		printf(KMAG "###PACKET:%d",++i);
		printf(KWHT ""); 
		//http://www.sflow.org/developers/diagrams/sFlowV5Sample.pdf
		//SKIP LAYERS(ETH,IP,UDP) TILL UDP SFLOW PACKET
		//ASSUME IPv4
		hexDump("P",packet,header->len);

		auto sFlowDatagramP=packet+42;
		try
		{
			++currentPacketNumber;
			printSFlowDatagram(sFlowDatagramP);
		}
		catch(uint8_t *)
		{
			std::cout<<"Error in "<<__FILE__<<" at line "<<__LINE__;
		}		
		printf(KMAG "\n###PACKET:%d END\n" KWHT,i);
	}
	//fclose (fp);
	printEvents(events);
	return(0);
}
//#define IFSZ 16
//#define FLTRSZ 120
//#define MAXHOSTSZ 256
//
//
//int
//usage(char *progname)
//{
//	printf("Usage: %s <interface> [<savefile name>]\n");
//	exit(11);
//}

//int main(int argc, char *argv[])
//{
//
//	pcap_t *p;               /* packet capture descriptor */
//	struct pcap_stat ps;     /* packet statistics */
//	pcap_dumper_t *pd;       /* pointer to the dump file */
//	char ifname[IFSZ];       /* interface name (such as "en0") */
//	char filename[80]=PCAP_SAVEFILE;       /* name of savefile for dumping packet data */
//	char errbuff[PCAP_ERRBUF_SIZE];  /* buffer to hold error text */
//	char lhost[MAXHOSTSZ];   /* local host name */
//	char fltstr[FLTRSZ];     /* bpf filter string */
//	char prestr[80];         /* prefix string for errors from pcap_perror */
//	struct bpf_program prog; /* compiled bpf filter program */
//	int optimize = 1;        /* passed to pcap_compile to do optimization */
//	int snaplen = 80;        /* amount of data per packet */
//	int promisc = 0;         /* do not change mode; if in promiscuous */
//	/* mode, stay in it, otherwise, do not */
//	int to_ms = 1000;        /* timeout, in milliseconds */
//	int count = 20;          /* number of packets to capture */
//	u_int32_t net = 0;         /* network IP address */
//	u_int32_t mask = 0;        /* network address mask */
//	char netstr[INET_ADDRSTRLEN];   /* dotted decimal form of address */
//	char maskstr[INET_ADDRSTRLEN];  /* dotted decimal form of net mask */
//	int linktype = 0;        /* data link type */
//	int pcount = 0;          /* number of packets actually read */
//
//
//	/*
//   * Open dump device for writing packet capture data. In this sample,
//   * the data will be written to a savefile. The name of the file is
//   * passed in as the filename string.
//   */
//	if ((pd = pcap_dump_open(p,filename)) == NULL) {
//		/*
//     * Print out error message if pcap_dump_open failed. This will
//     * be the below message followed by the pcap library error text,
//     * obtained by pcap_geterr().
//     */
//		fprintf(stderr,
//						"Error opening savefile \"%s\" for writing: %s\n",
//						filename, pcap_geterr(p));
//		exit(7);
//	}
//
//	/*
//   * Call pcap_dispatch() to read and process a maximum of count (20)
//   * packets. For each captured packet (a packet that matches the filter
//   * specified to pcap_compile()), pcap_dump() will be called to write
//   * the packet capture data (in binary format) to the savefile specified
//   * to pcap_dump_open(). Note that packet in this case may not be a
//   * complete packet. The amount of data captured per packet is
//   * determined by the snaplen variable which is passed to
//   * pcap_open_live().
//   */
//	if ((pcount = pcap_dispatch(p, count, &pcap_dump, (u_char *)pd)) < 0) {
//		/*
//     * Print out appropriate text, followed by the error message
//     * generated by the packet capture library.
//     */
//		sprintf(prestr,"Error reading packets from interface %s",
//						ifname);
//		pcap_perror(p,prestr);
//		exit(8);
//	}
//	printf("Packets received and successfully passed through filter: %d.\n",
//				 pcount);
//
//	/*
//   * Get and print the link layer type for the packet capture device,
//   * which is the network device selected for packet capture.
//   */
//	if (!(linktype = pcap_datalink(p))) {
//		fprintf(stderr,
//						"Error getting link layer type for interface %s",
//						ifname);
//		exit(9);
//	}
//	printf("The link layer type for packet capture device %s is: %d.\n",
//				 ifname, linktype);
//
//	/*
//   * Get the packet capture statistics associated with this packet
//   * capture device. The values represent packet statistics from the time
//   * pcap_open_live() was called up until this call.
//   */
//	if (pcap_stats(p, &ps) != 0) {
//		fprintf(stderr, "Error getting Packet Capture stats: %s\n",
//						pcap_geterr(p));
//		exit(10);
//	}
//
//	/* Print the statistics out */
//	printf("Packet Capture Statistics:\n");
//	printf("%d packets received by filter\n", ps.ps_recv);
//	printf("%d packets dropped by kernel\n", ps.ps_drop);
//
//	/*
//   * Close the savefile opened in pcap_dump_open().
//   */
//	pcap_dump_close(pd);
//	/*
//   * Close the packet capture device and free the memory used by the
//   * packet capture descriptor.
//   */
//	pcap_close(p);
//}
