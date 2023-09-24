#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

//myheader.h에서 필요한 구조체는 긁어오기

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, // IP header length
                     iph_ver:4; // IP version
  unsigned char      iph_tos; // Type of service
  unsigned short int iph_len; // IP Packet length (data + header)
  unsigned short int iph_ident; // Identification
  unsigned short int iph_flag:3, // Fragmentation flags
                     iph_offset:13; // Flags offset
  unsigned char      iph_ttl; // Time to Live
  unsigned char      iph_protocol; // Protocol type
  unsigned short int iph_chksum; // IP datagram checksum
  struct  in_addr    iph_sourceip; // Source IP address
  struct  in_addr    iph_destip;   // Destination IP address
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

// sniff_improved.c에서 got_packet의 기본 틀 사용
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 

    if (ip->iph_protocol == IPPROTO_TCP) { // tcp패킷인 경우를 추가
        int ip_header_len = ip->iph_ihl * 4; // 아이피 헤더 길이를 이용
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);

        printf("From MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", //맥주소를 바이트배열로 출력
               eth->ether_shost[0], eth->ether_shost[1],
               eth->ether_shost[2], eth->ether_shost[3],
               eth->ether_shost[4], eth->ether_shost[5]);

        printf("To MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               eth->ether_dhost[0], eth->ether_dhost[1],
               eth->ether_dhost[2], eth->ether_dhost[3],
               eth->ether_dhost[4], eth->ether_dhost[5]);

        printf("From IP: %s\n", inet_ntoa(ip->iph_sourceip));// ip주소 출력
        printf("To IP: %s\n", inet_ntoa(ip->iph_destip));
        printf("Source Port: %u\n", ntohs(tcp->tcp_sport));// 포트 주소 출력
        printf("Destination Port: %u\n", ntohs(tcp->tcp_dport));

        int payload_len = ntohs(ip->iph_len) - ip_header_len - TH_OFF(tcp) * 4; //ip헤더와 tcp헤더를 떼서 페이로드 출력
        if (payload_len > 0) {
            printf("Payload: ");
            int max_payload_len = (payload_len > 64) ? 64 : payload_len; // 64바이트까지만 출력
            for (int i = 0; i < max_payload_len; i++) {
                printf("%c", packet[sizeof(struct ethheader) + ip_header_len + TH_OFF(tcp) * 4 + i]);
            }
            printf("\n");
        } else {
            printf("No Payload\n"); //메시지가 없으면 no payload 출력
        }
    }
  }
}

// PCAP API
int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name ens33, 자기 주소에 맞게 수정해주기
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) != 0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   // Close the handle
  return 0;
}
