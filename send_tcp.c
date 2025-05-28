#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20

/*
    Notes:
    This is using raw sockets with AF_INET and IPPROTO_RAW
    The goal is to implement a TCP connection from 
    scratch, following the RFCs.
    This simply sends a single packet with no options
*/

// IP Header - RFC 791
// note that byte order matters for fields less than 8 bits. 
struct ip_header {
    uint8_t ihl:4, version:4; // RFC defines version as the first four bits, ihl as the last four bits
    uint8_t tos:8; 
    uint16_t total_length;
    uint16_t identification;
    uint8_t  flags:3;
    uint16_t fragment_offset:13;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
    // options and padding = 32 bits
};

// TCP Header - RFC 793
struct tcp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t reserved1:4, data_offset:4;
    uint8_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, // reverse order of rfc due to little endian-ness
            reserved2:2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
    // options (and padding) %  32 = 0
    // data
};
// options might include:
// MSS - Maximum Segment Size
// Window scaling
// Selective Acknowledgement Permitted
// Timestamps

// imaginary header used for tcp checksum calc
struct pseudo_header {
    uint32_t source_address;
    uint32_t destination_address;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

struct tcp_state {
    uint32_t client_initial_sequence;
    uint32_t server_initial_sequence;
    uint32_t client_current_sequence;
    uint32_t server_current_sequence;
    uint8_t conn_state;
};

struct internet_socket_address{
    uint16_t family;
    uint16_t port;
    struct internet_address {
        uint32_t address;
    } ip_address;
    uint8_t padding[8];
};

uint16_t checksum(const void* p, int num_bytes){
    // 16 bit one's complement sum of all 16 bit words in the header
    // checksum field is set to 0
    register int32_t sum = 0;
    register int16_t answer;
    uint16_t oddbyte;
    uint16_t *ptr = (uint16_t *)p;
    while(num_bytes >1) {
        sum += *ptr;
        ptr++;
        num_bytes -= 2;
    }
    if(num_bytes == 1) {
        oddbyte = 0;
        *((uint8_t *)&oddbyte) = *(uint8_t *)ptr; // odd byte should be treated as high byte of a 16 bit word
        sum += oddbyte;
    }
    // simulate 16 bit overflow w carry by folding
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);
    answer = ~sum;
    return answer;
}

void print_bytes(const void *p, int num_bytes) {
    for(int i = 0; i < num_bytes; i++) {
        printf("%02X ", ((uint8_t*)p)[i]);
    }
    printf("\n");
    for(int i = 0; i < num_bytes; i++) {
        printf("%08B ", ((uint8_t*)p)[i]);
    }
    printf("\n");
}

void build_pseudo_header(
    struct pseudo_header *ph,
    struct tcp_header *tcph,
    struct ip_header *iph,
    const void* options,
    uint16_t options_length,
    const void* tcp_payload,
    uint16_t tcp_payload_length
) {
    ph->source_address = iph->source_address;
    ph->destination_address = iph->destination_address;
    ph->reserved = 0;
    ph->protocol = iph->protocol;
    ph->tcp_length = htons(sizeof(struct tcp_header) + options_length + tcp_payload_length);
}

// prepend pseudo-header to tcp header, options, and data
void build_tcp_checksum(
    const struct pseudo_header *ph,
    struct tcp_header *tcph,
    const void* options,
    const uint16_t options_length,
    const void* data,
    const uint16_t data_length
) {
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcp_header) + data_length;
    // inefficient to malloc and free every time
    // should use a static buffer
    void* csum_buffer = malloc(psize);
    memcpy(csum_buffer, ph, sizeof(struct pseudo_header));
    memcpy(csum_buffer + sizeof(struct pseudo_header), tcph, sizeof(struct tcp_header));
    // what if you try to copy more data than the buffer can hold?
    // what if you data is null?
    // problematic?
    memcpy(csum_buffer + sizeof(struct pseudo_header) + sizeof(struct tcp_header), data, data_length);
    tcph->checksum = checksum(csum_buffer, psize);
    free(csum_buffer);
}



void send_tcp_packet(const uint32_t source_address, const uint16_t source_port, const uint32_t destination_address, const uint16_t destination_port, const uint32_t sequence_number, const uint32_t acknowledgement_number, const uint8_t flags, const void* data, const int data_length){
    printf("\nSENDING\n");
    const uint16_t total_length = sizeof(struct ip_header) + sizeof(struct tcp_header) + data_length;
    struct ip_header iph = {
        .version = 4,
        .ihl = 5,
        .tos = 0,
        .total_length = htons(total_length),
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = IPPROTO_TCP,
        .flags = 0,
        .header_checksum = 0,
        .source_address = source_address,
        .destination_address = destination_address,
    };
    iph.header_checksum = checksum(&iph, sizeof(struct ip_header));
    struct tcp_header tcph = {
        .source_port = source_port,
        .destination_port = destination_port,
        .sequence_number = sequence_number,
        .acknowledgment_number = acknowledgement_number,
        .reserved1 = 0, .reserved2 = 0,
        .data_offset = 5,
        .fin = (flags & 0x01) >> 0,
        .syn = (flags & 0x02) >> 1,
        .rst = (flags & 0x04) >> 2,
        .psh = (flags & 0x08) >> 3,
        .ack = (flags & 0x10) >> 4,
        .urg = (flags & 0x20) >> 5,
        .window = htons(32768),
        .checksum = 0,
        .urgent_pointer = 0,
    };
    struct pseudo_header ph;
    build_pseudo_header(&ph, &tcph, &iph, NULL,0, data, data_length);
    build_tcp_checksum(&ph, &tcph, NULL, 0, data, data_length);

    void* PDU = malloc(sizeof(struct ip_header) + sizeof(struct tcp_header) + data_length);
    memcpy(PDU, &iph, sizeof(struct ip_header));
    memcpy(PDU + sizeof(struct ip_header), &tcph, sizeof(struct tcp_header));
    memcpy(PDU + sizeof(struct ip_header) + sizeof(struct tcp_header), data, data_length);

    print_bytes(PDU, sizeof(struct ip_header) + sizeof(struct tcp_header) + data_length);

    struct internet_socket_address sin = {
        .family = AF_INET,
        .port = destination_port,
        .ip_address = {
            .address = destination_address
        }
    };
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sockfd < 0) {
        fprintf(stderr, "Error creating socket\n");
    }
    if(sendto(sockfd, PDU, total_length, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        fprintf(stderr, "Error sending packet\n");
    }

    free(PDU);
}




int main(int argc, char* argv[]) {
    if(argc != 5 && argc != 6) {
        fprintf(stderr, "Usage: %s <src_ip> <src_port> <dst_ip> <dst_port> [data]\n", argv[0]);
        return 1;
    }

    const char *src_ip = argv[1];
    int source_port =atoi(argv[2]);
    const char *dest_ip = argv[3];
    int dest_port = atoi(argv[4]);
    char* data = NULL;
    int data_length = 0;
    if(argc == 6) {
        data = argv[5];
        data_length = strlen(data);
    }

    send_tcp_packet(
        inet_addr(src_ip),
        htons(source_port),
        inet_addr(dest_ip),
        htons(dest_port), 
        htonl(0x1000),
        htonl(0x0),
        SYN,
        data,
        data_length 
    );

    return 0;
}