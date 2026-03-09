#include "ftp.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define MAX_PASV_PORTS 100

static int pasv_ports[MAX_PASV_PORTS]; //массив портов в pasv режиме
static int pasv_count = 0;

void ftp_init() {
    pasv_count = 0;
}

static void add_pasv_port(int port) {
    if (pasv_count < MAX_PASV_PORTS) {
        pasv_ports[pasv_count++] = port;
        printf("[FTP] PASV data port: %d\n", port);
    }
}

static int is_pasv_port(int port) {
    for (int i = 0; i < pasv_count; i++)
        if (pasv_ports[i] == port)
            return 1;
    return 0;
}

static void check_pasv_response(const unsigned char *payload, int len) {
    if (len <= 0) return;

    char buffer[512];
    int copy_len = len < sizeof(buffer) - 1 ? len : sizeof(buffer) - 1;
    memcpy(buffer, payload, copy_len);
    buffer[copy_len] = '\0';

    char *start = strstr(buffer, "227 Entering Passive Mode");
    if (!start) return;

    int h1,h2,h3,h4,p1,p2;
    if (sscanf(start, "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)",
               &h1,&h2,&h3,&h4,&p1,&p2) == 6) {
        int port = p1 * 256 + p2;
        add_pasv_port(port);
    }
}

int ftp_is_control(int src_port, int dst_port) {
    return src_port == 21 || dst_port == 21;
}

int ftp_is_data(int src_port, int dst_port) {
    return src_port == 20 || dst_port == 20 ||
           is_pasv_port(src_port) || is_pasv_port(dst_port);
}

void ftp_handle_control(
    struct in_addr src,
    struct in_addr dst,
    int src_port,
    int dst_port,
    const unsigned char *payload,
    int payload_len,
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    packet_queue *q_control)
{
    /*printf("[H1 FTP-CONTROL] %s:%d -> %s:%d\n",
           inet_ntoa(src), src_port,
           inet_ntoa(dst), dst_port);*/

    if (payload_len > 0)
        check_pasv_response(payload, payload_len);

    queue_push(q_control, header, packet);
}

void ftp_handle_data(
    struct in_addr src,
    struct in_addr dst,
    int src_port,
    int dst_port,
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    packet_queue *q_data)
{
    /*printf("[H2 FTP-DATA] %s:%d -> %s:%d\n",
           inet_ntoa(src), src_port,
           inet_ntoa(dst), dst_port);*/

    queue_push(q_data, header, packet);
}
