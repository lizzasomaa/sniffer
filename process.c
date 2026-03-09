#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <time.h>
#include <pthread.h>
#include "process.h"
#include "queue.h"
#include "ftp.h"
#include "tcp_sessions.h" 

packet_queue q_h1;
packet_queue q_h2;
packet_queue q_h3;
packet_queue q_h4;

int handle_udp_packet(struct in_addr src_addr,
                       struct in_addr dst_addr,
                       int src_port,
                       int dst_port,
                       int udp_payload_len)
{
    int client_port = src_port;  //отправитель = клиент

    if (client_port >= 20000 && client_port <= 25000) {
        time_t now = time(NULL);
        char timebuf[64];
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", localtime(&now));

        printf("Обработчик 4: %s пакет UDP %s:%d -> %s:%d игнорируется\n",
               timebuf,
               inet_ntoa(src_addr), src_port,
               inet_ntoa(dst_addr), dst_port);
        return 0;
    }

    return 1;
}

void process_packet(const struct pcap_pkthdr *header,
                    const unsigned char *packet,
                    pcap_dumper_t *dumper_h1,
                    pcap_dumper_t *dumper_h2,
                    pcap_dumper_t *dumper_h3,
                    pcap_dumper_t *dumper_h4)
{
    const unsigned char *ptr = packet;
    int len = header->caplen;

    if (len < sizeof(struct ether_header))
        return;

    const struct ether_header *eth = (const struct ether_header *)ptr;
    uint16_t eth_type = ntohs(eth->ether_type); //перевод из сетевого порядка

    ptr += sizeof(struct ether_header);
    len -= sizeof(struct ether_header);

    //берем структуру IPv4 пакета
    if (eth_type != ETHERTYPE_IP) {
        queue_push(&q_h4, header, packet);
        return;
    }

    if (len < sizeof(struct iphdr))
        return;

    const struct iphdr *ip_hdr = (const struct iphdr *)ptr;
    int ip_header_len = ip_hdr->ihl * 4;
    if (len < ip_header_len)
        return;

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_hdr->saddr; //source ip
    dst_addr.s_addr = ip_hdr->daddr; //dest ip

    //TCP
    if (ip_hdr->protocol == IPPROTO_TCP) {
        ptr += ip_header_len;
        len -= ip_header_len;

        if (len < sizeof(struct tcphdr))
            return;

        const struct tcphdr *tcp_hdr = (const struct tcphdr *)ptr;

        int src_port = ntohs(tcp_hdr->source);
        int dst_port = ntohs(tcp_hdr->dest);

        //FTP CONTROL
        if (ftp_is_control(src_port, dst_port)) {
            int tcp_header_len = tcp_hdr->doff * 4;

            //вытаскиваем данные, чтобы выявить переход в passive mode
            const unsigned char *tcp_payload = ptr + tcp_header_len;
            int tcp_payload_len = len - tcp_header_len;

            ftp_handle_control(
                src_addr, dst_addr,
                src_port, dst_port,
                tcp_payload, tcp_payload_len,
                header, packet,
                &q_h1
            );
        return;
    }

        //FTP DATA
        if (ftp_is_data(src_port, dst_port)) {
            ftp_handle_data(
            src_addr, dst_addr,
            src_port, dst_port,
            header, packet,
            &q_h2
        );
        return;
    }

        //TCP
        tcp_sessions_process_packet(
            header,
            packet,
            ip_hdr,
            tcp_hdr,
            &q_h3
        );
        return;
    }

    //UDP
    if (ip_hdr->protocol == IPPROTO_UDP) {
        ptr += ip_header_len;
        len -= ip_header_len;

        if (len < sizeof(struct udphdr))
            return;

        const struct udphdr *udp_hdr = (const struct udphdr *)ptr;

        int src_port = ntohs(udp_hdr->uh_sport);
        int dst_port = ntohs(udp_hdr->uh_dport);
        int udp_payload_len = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);

        int accepted = handle_udp_packet(src_addr, dst_addr,
                                         src_port, dst_port,
                                         udp_payload_len);

        if (!accepted)
            queue_push(&q_h4, header, packet);

        return;
    }

    //остальные пакеты
    queue_push(&q_h4, header, packet);
}

void process_pcap_file(const char *filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    ftp_init();

    pcap_t *handle = pcap_open_offline(filepath, errbuf);
    if (handle == NULL) return;

    pcap_dumper_t *dumper_h1 = pcap_dump_open(handle, "ftp.pcap");
    pcap_dumper_t *dumper_h2 = pcap_dump_open(handle, "ftp_data.pcap");
    pcap_dumper_t *dumper_h3 = pcap_dump_open(handle, "tcp_clean.pcap");
    pcap_dumper_t *dumper_h4 = pcap_dump_open(handle, "other.pcap");

    pthread_t th1, th2, th3, th4;
    queue_init(&q_h1);
    queue_init(&q_h2);
    queue_init(&q_h3);
    queue_init(&q_h4);

    thread_arg a1 = { &q_h1, dumper_h1, "FTP CONTROL" };
    thread_arg a2 = { &q_h2, dumper_h2, "FTP DATA" };
    thread_arg a3 = { &q_h3, dumper_h3, "TCP CLEAN" };
    thread_arg a4 = { &q_h4, dumper_h4, "OTHER" };

    pthread_create(&th1, NULL, writer_thread, &a1);
    pthread_create(&th2, NULL, writer_thread, &a2);
    pthread_create(&th3, NULL, writer_thread, &a3);
    pthread_create(&th4, NULL, writer_thread, &a4);

    printf("Opened PCAP file: %s\n", filepath);

    struct pcap_pkthdr *header;
    const unsigned char *data;
    int packet_count = 0;

    while (pcap_next_ex(handle, &header, &data) >= 0) {
        packet_count++;
        process_packet(header, data, dumper_h1, dumper_h2, dumper_h3, dumper_h4);
    }


    printf("Finished reading %d packets from %s\n\n", packet_count, filepath);
    queue_finish(&q_h1);
    queue_finish(&q_h2);
    queue_finish(&q_h3);
    queue_finish(&q_h4);

    pthread_join(th1, NULL);
    pthread_join(th2, NULL);
    pthread_join(th3, NULL);
    pthread_join(th4, NULL);

    pcap_dump_close(dumper_h1);
    pcap_dump_close(dumper_h2);
    pcap_dump_close(dumper_h3);
    pcap_dump_close(dumper_h4);

    pcap_close(handle);
}

void process_directory(const char *dirpath) {
    struct dirent *entry;
    DIR *dir = opendir(dirpath);

    if (dir == NULL) {
        perror("opendir failed");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char *ext = strrchr(entry->d_name, '.');
        if (ext && strcmp(ext, ".pcap") == 0) {
            char fullpath[1024];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
            process_pcap_file(fullpath);
        }
    }

    closedir(dir);
}