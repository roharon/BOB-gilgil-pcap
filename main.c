
#include <stdio.h>
#include <stdbool.h>
#include <pcap/pcap.h>
#include <stdint.h>

#define TCP 6
#define IPv4 0x0800

#define IP 301
#define MAC 302

#define SIZE(x,y) sizeof(x)/sizeof(y)

/*
 * IPv4 에서 Protocol 을 확인 UDP(Int 17), TCP(Int 6)
 *
 * TCP는 Src Port, Dst Port, Seq, Ack, Len
 *
 * UDP는 Src Port, Dst Port
 *
 * 자세한 내용 스크린샷 찍어두었다.
 */

typedef struct{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint8_t Type[2];
}ethernet_type;

typedef struct{
    uint8_t* Dip;
    uint8_t* Sip;
    uint8_t protocol[1];
}ip_type;

typedef struct{
    uint8_t Dport[2];
    uint8_t Sport[2];
    uint8_t Seq[4];
    uint8_t Ack[4];
    uint8_t Len;
}tcpudp_type;

typedef struct{
    ethernet_type ethernetType;
    ip_type ipType;
    tcpudp_type tcpudpType;
}my_packet;


void usage() {
    printf("syntax: pcap_test <interface>\n");
    printf("sample: pcap_test wlan0\n");
}

void print_mac(uint8_t *mac) {
    printf("%02X %02X %02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(uint8_t *ip){
    printf("%u.%u.%u.%u\n", ip[0],ip[1],ip[2],ip[3]);
}

void print_port(uint8_t *port){
    printf("%u\n", ((((port[0] & 0xFF)<< 8) | port[1])));
}

uint16_t get_port(uint8_t *port){
    return (((port[0] & 0xFF)<< 8) | port[1]);
}

void print_type(uint8_t *port){
    printf("%u%u\n", port[0],port[1]);
}

void print_protocol(uint8_t* protocol){
    printf("%u\n", protocol[0]);
}

uint16_t my_ntohs(uint16_t n) {
    return (n >> 8) | ((n & 0x00FF) << 8);
}

void init_ether(ethernet_type *pck, const uint8_t* data){
    //pck->Type[0], pck->Type[1] = data[12], data[13];
    pck->Type[0] = data[12];
    pck->Type[1] = data[13];

    // Ethernet-Type check

    for(int i = 0; i<6; i++){
        pck->Dmac[i] = data[i];
        pck->Smac[i] = data[i+6];
    }
}

void init_ip(ip_type *pck, const uint8_t* data){
    data = (uint8_t*)data;
    for(int i = 0; i<4; i++){
        pck->Dip[i] = data[30+i];
        pck->Sip[i] = data[26+i];
    }

    pck->protocol[0] = data[23];
}

void init_tcp(tcpudp_type *pck, const uint8_t* data){
    pck->Dport[0] = data[34];
    pck->Dport[1] = data[35];
    pck->Sport[0] = data[36];
    pck->Sport[1] = data[37];

    for(int i =0; i<4; i++){
        pck->Seq[i] = data[38 + i];
        pck->Ack[i] = data[42 + i];
    }

}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        usage();
        return -1;
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t * packet;
        my_packet pck;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("----------------------\n");
        printf("%u bytes captured\n", header->caplen);

        init_ether(&(pck.ethernetType), packet);
        if(pck.ethernetType.Type[0] == 0x08 && pck.ethernetType.Type[1] == 0x00) {
            //IPv4
            init_ip(&(pck.ipType), packet);

            if(pck.ipType.protocol[0] != 0x06){
                printf("TCP");
                init_tcp(&(pck.tcpudpType), packet);

                if(get_port(pck.tcpudpType.Sport) == 443 || get_port(pck.tcpudpType.Dport) == 443){
                    printf("| protocol - SSL");
                }
                else if(get_port(pck.tcpudpType.Sport) == 80 || get_port(pck.tcpudpType.Dport) == 80){
                    printf("| protocol - http");
                }
                printf("\n");
            }
            else if(pck.ipType.protocol[0] == 0x17){
                // UDP
                printf("UDP - ");
                init_tcp(&(pck.tcpudpType), packet);
            }
        }

        //printf("%d\n", pck.ipType.protocol);
        //printf("The answer is : %x\n", packet[23]);
        //printf("%x %x\n", pck.ethernetType.Type[0], pck.ethernetType.Type[1]);
        //printf("The answer is : %x %x\n", packet[12], packet[13]);
        //printf("size is : %ld\n", sizeof(pck.ethernetType.Type));
        //printf("size is : %ld\n", sizeof(pck.ipType.protocol));

        printf("Smac : ");
        print_mac(pck.ethernetType.Smac);

        printf("Dmac : ");
        print_mac(pck.ethernetType.Dmac);

        printf("Type : ");
        print_type(pck.ethernetType.Type);

        printf("Sip : ");
        print_ip(pck.ipType.Sip);

        printf("Dip : ");
        print_ip(pck.ipType.Dip);

        printf("Protocol : ");
        print_protocol(pck.ipType.protocol);

        printf("Sport : ");
        print_port(pck.tcpudpType.Sport);

        printf("Dport : ");
        print_port(pck.tcpudpType.Dport);




        //TODO printValueDec 작동확인함.


        // 사이즈 파라미터는 함수내부에서 처리할수있게 해보자.
        // 나머지는 멘토님 강의보고 결과물 작성.
    }

    pcap_close(handle);
    return 0;
}
