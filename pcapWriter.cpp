#define PCAP_WRITEFILE "pcapWriterTest.pcap"
#define PCAP_READFILE "../sflow.pcap"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>
#include <queue>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>//
#include <cstring>


FILE *pFile = fopen("outputInfo.txt", "w");

void hexDump(const char *desc, const void *addr, int len);

int extract_sFlow_fs_hs_Ethernet(u_char *fs_HS_Packet) {
  fprintf(pFile, "\n\t\t\t\t###Ethernet Record");
  auto sFS_RP_HS_Type = __bswap_16(*reinterpret_cast<uint16_t const *>(fs_HS_Packet + 12));

  fprintf(pFile, "\n"
          "\t\t\t\tsFS_RP_HS_Type:\t%02x\n", sFS_RP_HS_Type
  );
  auto layer3 = fs_HS_Packet + 14;

  if (sFS_RP_HS_Type == 0x0800) {
    //SET IP ADDRESS TO 0
    int *ipS = (int *) (layer3 + 12);
    *ipS = 0;
    int *ipH = (int *) (layer3 + 16);
    *ipH = 0;
    //size_t header_size=(*layer3 & 0x0f)*4;
    //layer4_proto=*(layer3+9);
    //layer4=layer3+header_size;
  } else if (sFS_RP_HS_Type == 0x86dd) {
    int *ipS = (int *) (layer3 + 8);
    *ipS = 0;
    int *ipS1 = (int *) (layer3 + 12);
    *ipS1 = 0;
    int *ipS2 = (int *) (layer3 + 16);
    *ipS2 = 0;
    int *ipS3 = (int *) (layer3 + 20);
    *ipS3 = 0;

    int *ipH = (int *) (layer3 + 24);
    *ipH = 0;
    int *ipH1 = (int *) (layer3 + 28);
    *ipH1 = 0;
    int *ipH2 = (int *) (layer3 + 32);
    *ipH2 = 0;
    int *ipH3 = (int *) (layer3 + 36);
    *ipH3 = 0;

  } else {
    printf("Sflow Sample Packet not expected format (IPv4 or IPv6)...\n");
    return -10;
  }

  fprintf(pFile, "\t\t\t\t###Ethernet Record END\n\n");
}

int extract_sf_flowSample(u_char *fsPacket) {
  auto sFS_FlowRecord = __bswap_32(*reinterpret_cast<uint32_t const *>(fsPacket + 28));
  fprintf(pFile, "\n"
          "\t\tsFS_FlowRecord:\t%02x\n", sFS_FlowRecord
  );
  u_char *fsRawPacket = fsPacket + 32;
  for (int i = 0; i < sFS_FlowRecord; i++) {
    //
    fprintf(pFile, "\n\t\t\t###Flow Record:%d", i + 1);

    auto sFS_FR_PacketHeaderV = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket));
    auto sFS_FR_FormatV = sFS_FR_PacketHeaderV & 0X00000FFF;
    auto sFS_FR_FlowDataLength = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 4));
    if (sFS_FR_FormatV == 1) {
      //###RAW PACKET HEADER:RP

      auto sFS_FR_RP_HeaderProtocol = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 8));
      auto sFS_FR_RP_OriginalPacketLength = __bswap_32(*reinterpret_cast<uint32_t const *>(fsRawPacket + 20));
      fprintf(pFile, "\n"
                      "\t\t\tsFS_RP_FormatV:\t\t\t%02x\n"
                      "\t\t\tsFS_RP_FlowDataLength:\t\t%02x\n"
                      "\t\t\tsFS_RP_OriginalPacketLength:\t%02x\n"
                      "\t\t\tsFS_RP_HeaderProtocol:\t\t%02x\n", sFS_FR_FormatV, sFS_FR_FlowDataLength,
              sFS_FR_RP_OriginalPacketLength, sFS_FR_RP_HeaderProtocol
      );
      if (sFS_FR_RP_HeaderProtocol == 1) {

        extract_sFlow_fs_hs_Ethernet(fsRawPacket + 24);

      } else {
        printf("Not implemented..FS->FR->HeaderProtocol expected:ethernet\n");
        return -1;
      }
    } else {
      fprintf(pFile,"\nNot implemented..FS->RP->Format expected:Raw Packet Header\n");
    }

    fsRawPacket = fsRawPacket + sFS_FR_FlowDataLength + 8;
    fprintf(pFile, "\t\t\t###Flow Record:%d END###\n", i + 1);

  }
}

int extract_sFlow(u_char *sPacketP) {

  auto sDatagramVersionV = __bswap_32(*reinterpret_cast<uint32_t const *>(sPacketP));
  if (!(sDatagramVersionV == 2 || sDatagramVersionV == 4 || sDatagramVersionV == 5)) {
    printf("\nsDatagramVersionV should be 2,4 or 5\n");
    return -20;
  }

  auto sAddressTypeV = __bswap_32(*reinterpret_cast<uint32_t const *>(sPacketP + 4));

  u_char *sSubAgentIdP;
  //IPV4 ? V6
  if (sAddressTypeV == 1) {
    sSubAgentIdP = sPacketP + 12;
  } else if (sAddressTypeV == 2) {
    sSubAgentIdP = sPacketP + 24;
  } else {
    printf("Sflow AddressType problem AddressType should be in not IPv4 or IPv6..\n");
    return 1;
  }
  auto sSubAgentIdV = *reinterpret_cast<uint32_t const *>(sSubAgentIdP);
  //----OTHER HEADER FIELDS
  //----HERE

  //
  //sSubAgentIdP is the new Packet Pointer
  auto sNumSamplesP = sSubAgentIdP + 12;
  auto sNumSamplesV = __bswap_32(*reinterpret_cast<uint32_t const *>(sNumSamplesP));

  fprintf(pFile, "\n--\n"
          "sDatagramVersionV:\t%02x\n"
          "sAddressTypeV:\t\t%02x\n"
          "sSubAgentIdV:\t\t%02X\n"
          "sNumSamplesV:\t\t%02X\n"
          "\n", sDatagramVersionV, sAddressTypeV, sSubAgentIdV, sNumSamplesV
  );

  //READ SFLOW SAMPLES
  auto sFlowP = sSubAgentIdP + 16;
  for (int i = 0; i < sNumSamplesV; i++) {
    fprintf(pFile, "\n\t###Flow Sample:%d\n", i + 1);
    auto sFlowSampleHeaderV = __bswap_32(*reinterpret_cast<uint32_t const *>(sFlowP));
    auto sFlowSampleTypeV = sFlowSampleHeaderV & 0X00000FFF;
    auto sFlowSampleLength = __bswap_32(*reinterpret_cast<uint32_t const *>(sFlowP + 4));

    fprintf(pFile, "\n"
            "\tsFlowSampleTypeV:\t%02x\n"
            "\tsFlowSampleLength:\t%02x\n", sFlowSampleTypeV, sFlowSampleLength
    );

    //enterprise=0,format=1
    if (sFlowSampleTypeV == 1) {
      //READ FLOW Sample
      extract_sf_flowSample(sFlowP + 8);
    } else {
      printf("\nCounter Samples are not implemented\n");
    }
    //NEXT Sflow PACKET
    sFlowP = (sFlowP + 8 + sFlowSampleLength);
    fprintf(pFile, "\n\t###Flow Sample:%d END###\n", i + 1);
  }
}

int extract_ethernet(u_char *pHead) {
//IP version
  auto layer2_type = __bswap_16(*reinterpret_cast<uint16_t *>(pHead + 12));
//hexDump("",&(ipV),2);
  auto layer3 = pHead + 14;
  u_char *layer4;
  u_char layer4_proto;
//IPv4
  if (layer2_type == 0x0800) {
    //SET IP ADDRESS OF MAIN PACKET(NOT SFLOW SAMPLES) TO 0
    int *ipS = (int *) (layer3 + 12);
    *ipS = 0;
    int *ipH = (int *) (layer3 + 16);
    *ipH = 0;
    size_t header_size = (*layer3 & 0x0f) * 4;
    layer4_proto = *(layer3 + 9);
    layer4 = layer3 + header_size;


  } else if (layer2_type == 0x86dd) {
    int *ipS = (int *) (layer3 + 8);
    *ipS = 0;
    int *ipH = (int *) (layer3 + 24);
    *ipH = 0;
    layer4_proto = *(layer3 + 6);
    layer4 = layer3 + 40;
    //TODO IPV6 128 bit
  } else {
    fprintf(pFile, "Packet not expected format (IPv4 or IPv6)...");
    return -10;
  }
  if (layer4_proto == IPPROTO_UDP) {
    extract_sFlow(layer3 + 28);
  } else {
    fprintf(pFile, "Sflow Packet should be UDP..");
    return -11;
  }
}

int main(int argc, char *argv[]) {
  char *write_filename; //= PCAP_WRITEFILE;
  char *read_filename; //= PCAP_READFILE;
  if (argc != 3) {
    printf("argument count is:%d, expected:2\n", argc);
    exit(1);
  }
  read_filename=argv[1];
  write_filename=argv[2];

  std::cout << "Reading File::" << read_filename << std::endl;
  std::cout << "Writing File::" << write_filename << std::endl;

  char errbuff[PCAP_ERRBUF_SIZE];

  //OPEN READ FILE
  pcap_t *handlerReading = pcap_open_offline(read_filename, errbuff);
  if (handlerReading == NULL) {
    fprintf(pFile, "Reading File error...");
    exit(1);
  }

  pcap_dumper_t *handlerDumper = pcap_dump_open(handlerReading, write_filename);

  //printf("%s",pcap_geterr(handlerDumper));

  if (handlerDumper == NULL) {
    printf("Writing File error...");
    exit(2);
  }


  //The header that pcap gives us
  struct pcap_pkthdr *header;

  //The actual packet
  const u_char *packet;

  int i = 0;
  while (pcap_next_ex(handlerReading, &header, &packet) >= 0) {
    u_char *payload = (u_char *) malloc(header->len * sizeof(u_char));
    memcpy(payload, packet, header->len * sizeof(u_char));

    fprintf(stdout, "###PACKET:%d", ++i);
    extract_ethernet(payload);

    fprintf(stdout, "\n###PACKET:%d END\n", i);

    pcap_dump((u_char *) handlerDumper, header, payload);

  }
  printf("Done..");
  pcap_dump_close(handlerDumper);
  /*
   * Close the packet capture device and free the memory used by the
   * packet capture descriptor.
   */
  pcap_close(handlerReading);
  return 0;
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
