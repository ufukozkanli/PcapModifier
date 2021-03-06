#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>
#include <queue>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define SFLOWFILEPRINTTYPE 0
FILE *fp = stdout;//fopen ( "pcapTestResult.txt", "w" ) ;
FILE *fp_e = stdout;//fopen ( "pcapTestResultEvents.txt", "w" ) ;
#define debug_print(type, ...)\
  do { if (type==0 && SFLOWFILEPRINTTYPE<=type) fprintf(fp, __VA_ARGS__); else if(type==1 && SFLOWFILEPRINTTYPE<=type) fprintf(fp_e, __VA_ARGS__);else if(type>2 && SFLOWFILEPRINTTYPE<=type) fprintf(stdout,__VA_ARGS__); } while (0)




#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

/// @relates ec
template <class... Ts>
std::string make_error(void* x, Ts&&... xs) {
  return "";
}
namespace ec
{
const char * format_error="";
}


struct temp_event {
  uint16_t port_s;
  uint16_t port_d;
  int type;//tcp udp icmp
  //TODO Pointer for IPv6 128bit
  uint32_t ip_address_s;
  uint32_t ip_address_d;
  uint32_t packet_number;
};
std::vector<temp_event> events;
temp_event current_event = {};
uint32_t current_packet_number;



void hexDump(const char *desc, const void *addr, int len);





int read_header(const u_char *rp_header_packet,uint32_t pack_length) {
  //TODO Create Single Function both sflow samples and pcap samples (SIMILAR FUNCTION IN PCAP HEADER READER)
  current_event = {};
  current_event.packet_number = ++current_packet_number;
  debug_print(1, KMAG
          "\n\t\t\t\t###Ethernet Record");

  auto layer2_type = __bswap_16(*reinterpret_cast<uint16_t const *>(rp_header_packet + 12));
  debug_print(1, "\n"
          "\t\t\t\tlayer2_type:\t%02x\n", layer2_type
  );
  auto layer3 = rp_header_packet + 14;
  const u_char *layer4;
  u_char layer4_proto;
  //Check IPv4 or IPv6
  switch (layer2_type) {
    default: {
      debug_print(3,"Format:0x%02x Expected format (IPv4(0x800) or IPv6(0x86dd))\n",layer2_type);
      return -10;
    }
    case 0x0800: {
      //IPv4
      size_t header_size = (*layer3 & 0x0f) * 4;
      layer4_proto = *(layer3 + 9);
      layer4 = layer3 + header_size;
      auto orig_h = *reinterpret_cast<uint32_t const *>(layer3 + 12);
      auto resp_h = *reinterpret_cast<uint32_t const *>(layer3 + 16);

      struct in_addr ipS, ipD;
      ipS.s_addr = orig_h;
      ipD.s_addr = resp_h;
      debug_print(1, "\n"
              "\t\t\t\t\tips:\t%s\n"
              "\t\t\t\t\tipD:\t%s\n", inet_ntoa(ipS), inet_ntoa(ipD)
      );

      current_event.ip_address_s= orig_h;
      current_event.ip_address_d = resp_h;
    }
      break;
    case 0x86dd: {
//IPv6
      layer4_proto = *(layer3 + 6);
      layer4 = layer3 + 40;
      //TODO 128 IPv6
      auto orig_h = *reinterpret_cast<uint32_t const *>(layer3 + 8);
      auto resp_h = *reinterpret_cast<uint32_t const *>(layer3 + 24);
      current_event.ip_address_s= orig_h;
      current_event.ip_address_d = resp_h;
    }
      break;
  }

  current_event.type=layer4_proto;
  if (layer4_proto == IPPROTO_TCP) {
    auto orig_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    current_event.port_s = orig_p;
    current_event.port_d = resp_p;
  } else if (layer4_proto == IPPROTO_UDP) {
    auto orig_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    current_event.port_s = orig_p;
    current_event.port_d = resp_p;
  } else if (layer4_proto == IPPROTO_ICMP) {
    auto message_type = *reinterpret_cast<uint8_t const *>(layer4);
    auto message_code = *reinterpret_cast<uint8_t const *>(layer4 + 1);
    current_event.port_s = message_type;
    current_event.port_d = message_code;
  } else if (layer2_type==0x86dd && layer4_proto == IPPROTO_ICMPV6) {
    auto message_type = *reinterpret_cast<uint8_t const *>(layer4);
    auto message_code = *reinterpret_cast<uint8_t const *>(layer4 + 1);
    current_event.port_s = message_type;
    current_event.port_d = message_code;
  } else if (layer4_proto == IPPROTO_DCCP) {
    auto orig_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    current_event.port_s = orig_p;
    current_event.port_d = resp_p;
    debug_print(1, "--DCCP_Type:%02x--",(*reinterpret_cast<uint8_t const *>(layer4+8)&0b00011110)>>1);
  }else if (layer4_proto == IPPROTO_SCTP) {
    auto orig_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4));
    auto resp_p = __bswap_16(*reinterpret_cast<uint16_t const *>(layer4 + 2));
    current_event.port_s = orig_p;
    current_event.port_d = resp_p;
    debug_print(1, "--SCTP_Type:%02x--",*reinterpret_cast<uint8_t const *>(layer4+12));
  }

  else {
    debug_print(1, "\nType:%02x Only Sflow TCP,UDP and CMP  implemented..\n",layer4_proto);
    return -11;
  }

  struct in_addr ipS, ipD;
  ipS.s_addr = current_event.ip_address_s;
  ipD.s_addr = current_event.ip_address_d;

  debug_print(1, "\n###PACKET:%d Event:%d####\n"
          "PortS:%d\n"
          "PortP:%d\n"
          "IdAddressS:%s\n"
          "IdAddressP:%s\n"
          "\n", current_event.packet_number, 0, current_event.port_s, current_event.port_d, inet_ntoa(ipS),
              inet_ntoa(ipD)
  );


//        connection conn;
//        conn.src = {&current_event.ip_address_s, address::ipv4, address::network};
//        conn.dst = {&current_event.ip_address_d, address::ipv4, address::network};
//        conn.sport = {current_event.port_s, port::tcp};
//        conn.dport = {current_event.port_d, port::tcp};
//        //printf("a::%02x\n",current_event.ip_address_s);
//
//        vector sFpacket;
//        vector meta;
//        meta.emplace_back(std::move(conn.src));
//        meta.emplace_back(std::move(conn.dst));
//        meta.emplace_back(std::move(conn.sport));
//        meta.emplace_back(std::move(conn.dport));
//        sFpacket.emplace_back(std::move(meta));
//        auto str = reinterpret_cast<char const*>(data + 14);
//        sFpacket.emplace_back(std::string{str, packet_size});
//        event e{{std::move(sFpacket), packet_type_}};
//        e.timestamp(timestamp::clock::now());
//
//
//        //???e.timestamp(def.ts);
//        event_queue_.push_back(std::move(e));

  //packet_string_ = packet_stream_.str();
  //VAST_DEBUG(this, packet_string_ << "\n");
  //packet_stream_.str(std::string());

  return 0;
}

int read_sflow_flowsample(const u_char *fs_packet) {
  //Number Of Flow Records
  auto fs_flow_record = __bswap_32(*reinterpret_cast<uint32_t const *>(fs_packet + 28));
  debug_print(1, "\n"
          "\t\tsFS_FlowRecord:\t%02x\n", fs_flow_record
  );
  //Points to First Flow Records
  const u_char *fs_frecord_packet = fs_packet + 32;

  for (int i = 0; i < static_cast<int>(fs_flow_record); i++) {
    //
    debug_print(2, KCYN
            "\n\t\t\t###Flow Record:%d", i + 1);

    auto fr_data_format = __bswap_32(*reinterpret_cast<uint32_t const *>(fs_frecord_packet));
    auto fr_format = fr_data_format & 0X00000FFF;
    auto fr_flow_data_length = __bswap_32(*reinterpret_cast<uint32_t const *>(fs_frecord_packet + 4));

    auto fs_flow_data = fs_frecord_packet + 8;
    //Check Flow Data Format
    // 1=Raw Packet Header
    // 2=Ethernet Frame
    // 3=IPv4
    // 4=IPv6
    // 1001=Extended Switch Data
    // 1002=Extended Router Data
    if (fr_format == 1) {
      //Raw Packet Header
      auto fs_raw_header_protocol = __bswap_32(*reinterpret_cast<uint32_t const *>(fs_flow_data));
      auto fs_raw_header_size = __bswap_32(*reinterpret_cast<uint32_t const *>(fs_flow_data + 12));
      debug_print(1, "\n"
              "\t\t\tsFS_RP_FormatV:\t\t\t%02x\n"
              "\t\t\tsFS_RP_FlowDataLength:\t\t%02x\n"
              "\t\t\tsFS_RP_OriginalPacketLength:\t%02x\n"
              "\t\t\tsFS_RP_HeaderProtocol:\t\t%02x\n", fr_format, fr_flow_data_length,
                  fs_raw_header_size, fs_raw_header_protocol
      );
      //Check Header Protocol
      //ETHERNET-ISO88023    = 1,
      //ISO88024-TOKENBUS    = 2,
      //ISO88025-TOKENRING   = 3,
      //FDDI                 = 4,
      //FRAME-RELAY          = 5,
      //X25                  = 6,
      //PPP                  = 7,
      //SMDS                 = 8,
      //AAL5                 = 9,
      //AAL5-IP              = 10, /* e.g. Cisco AAL5 mux */
      //IPv4                 = 11,
      //IPv6                 = 12,
      //MPLS                 = 13,
      //POS                  = 14  /* RFC 1662, 2615 */
      if (fs_raw_header_protocol == 1) {
        //###Ethernet Frame Data:
        //TODO HeaderSize checking
        read_header(fs_flow_data + 16,fs_raw_header_size);
      } else {
        debug_print(1, "Not implemented..FS->FR->HeaderProtocol\n");
      }
    } else {
      debug_print(1, "Not implemented..FS->RP->Format\n");
    }
    //Point to next Flow Record(Previous poiner+length of data + 8bits header info)
    fs_frecord_packet = fs_frecord_packet + fr_flow_data_length + 8;

    debug_print(1, KCYN
            "\t\t\t###Flow Record:%d END###\n"
            KWHT, i + 1);

  }
  return 0;
}

int read_sflow_datagram(const u_char *s_packet) {
  //CHECK IF UDP PACKET IS  SFLOW
  auto datagram_ver = __bswap_32(*reinterpret_cast<uint32_t const *>(s_packet));
  if (!(datagram_ver == 2 || datagram_ver == 4 || datagram_ver == 5))
    return -1;
  auto s_address_type = __bswap_32(*reinterpret_cast<uint32_t const *>(s_packet + 4));

  int ip_length = 0;
  //Agent Address IPV4 ? if agent address is V4 skip 4 bytes V6 skip  16 bytes
  if (s_address_type == 1) {
    ip_length = 4;
  } else if (s_address_type == 2) {
    ip_length = 16;
  } else {
    debug_print(1, "Sflow IP Header Problem..\n");
    //auto err = std::string{::pcap_geterr(pcap_)};
    //return make_error(ec::format_error, "failed to get next packet: ", err);
    return -10;
  }
  //TOTAL Number of SFLOW Samples
  auto num_samples = __bswap_32(*reinterpret_cast<uint32_t const *>(s_packet + ip_length + 20));

  debug_print(3, "SampleCount:%d\n",num_samples);

  //FOR EACH SFLOW Samples
  //points to first sample packet
  const u_char *sample_packet = s_packet + ip_length + 24;
  for (int i = 0; i < static_cast<int>(num_samples); i++) {


    debug_print(1, KGRN
            "\n\t###Flow Sample:%d\n", i + 1);
    auto sflow_sample_header = __bswap_32(*reinterpret_cast<uint32_t const *>(sample_packet));
    auto sflow_sample_type = sflow_sample_header & 0X00000FFF;
    auto sflow_sample_length = __bswap_32(*reinterpret_cast<uint32_t const *>(sample_packet + 4));

    debug_print(1, "\n"
            "\tsFlowSampleTypeV:\t%02x\n"
            "\tsFlowSampleLength:\t%02x\n", sflow_sample_type, sflow_sample_length
    );
    //Samples TYPE (Flow sample or Counter Sample) enterprise=0,format=1
    if (sflow_sample_type == 1) {
      //dissect FLOW Sample
      read_sflow_flowsample(sample_packet + 8);
    } else {
      debug_print(1, "Counter Samples are not implemented");
    }
    //Points to next Sflow PACKET (Header 8 bytes + samplelength)
    sample_packet = (sample_packet + 8 + sflow_sample_length);
    debug_print(1, KGRN
            "\n\t###Flow Sample:%d END###\n"
            KWHT, i + 1);
  }
  return 0;
}

int printEvents(std::vector<temp_event> &list) {
  int i = 0;
  for (std::vector<temp_event>::iterator it = list.begin(); it != list.end(); ++it) {
    if(it->type!=IPPROTO_ICMP)
    {
      continue;
    }
    struct in_addr ipS, ipD;
    ipS.s_addr = it->ip_address_s;
    ipD.s_addr = it->ip_address_d;

    printf("\n###PACKET:%d Event:%d####\n"
                   "PortS:%d\n"
                   "PortP:%d\n"
                   "IdAddressS:%s\n"
                   "IdAddressP:%s\n"
                   "\n", it->packet_number, ++i, it->port_s, it->port_d, inet_ntoa(ipS), inet_ntoa(ipD)
    );
  }
}

void hexDump(const char *desc, const void *addr, int len) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *) addr;

  // Output description if given.
  if (desc != NULL)
    printf("%s:\n", desc);

  if (len == 0) {
    printf("  ZERO LENGTH\n");
    return;
  }
  if (len < 0) {
    printf("  NEGATIVE LENGTH: %i\n", len);
    return;
  }

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).
    if ((i % 8) == 0 && i != 0)
      printf(" ");
    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)
        printf("  %s\n", buff);

      // Output the offset.
      printf("  %04x ", i);
    }

    // Now the hex code for the specific character.
    printf(" %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    printf("   ");
    i++;
  }

  // And print the final ASCII bit.
  printf("  %s\n", buff);
}

int main(int argc, char *argv[]) {

argv[1]="/home/nobodylinux/Desktop/_Programming/PcapSample/samples/sctp.cap";
  if (argc < 2) {
    printf("File input expected%d", argc);
    exit(1);
  }

  //get file
  char *filename = argv[1];
  std::cout << "Processing File::" << filename << std::endl;
  //error buffer
  char errbuff[PCAP_ERRBUF_SIZE];

  //open file and create pcap handler
  pcap_t *handler = pcap_open_offline(filename, errbuff);
  if (handler == NULL) {
    printf("File error...");
    exit(1);
  }
  //The header that pcap gives us
  struct pcap_pkthdr *header;

  //The actual packet
  const u_char *packet;

  //write to file
  //FILE *fp = fopen ( "pcapTestResult.txt", "w" ) ;


  while (pcap_next_ex(handler, &header, &packet) >= 0) {
    //READ PCAP PACKETS
    debug_print(100,KMAG "###PACKET:%d\n", current_packet_number);
    printf(KWHT "");
    //http://www.sflow.org/developers/diagrams/sFlowV5Sample.pdf
    //SKIP LAYERS(ETH,IP,UDP) TILL UDP SFLOW PACKET
    //ASSUME IPv4
    //hexDump("P",packet,header->len);

    auto sFlowDatagramP = packet + 42;
    try {
      //read_sflow_datagram(sFlowDatagramP);
      read_header(sFlowDatagramP-42,header->len);
    }
    catch (uint8_t *) {
      std::cout << "Error in " << __FILE__ << " at line " << __LINE__;
    }

  }
  //fclose (fp);
  printEvents(events);
  return (0);
}
