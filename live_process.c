#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>

#include "process.h"
#include "queue.h"
#include "ftp.h"
#include "tcp_sessions.h"
#include "live_process.h"

extern packet_queue q_h1;
extern packet_queue q_h2;
extern packet_queue q_h3;
extern packet_queue q_h4;

static volatile int stop_capture = 0;

static void handle_sigint(int sig) {
    stop_capture = 1;
}

void process_live_interface(const char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    ftp_init();

    signal(SIGINT, handle_sigint);

    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }

    printf("Listening on interface: %s... Press Ctrl+C to stop\n", interface);

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

    struct pcap_pkthdr *header;
    const unsigned char *data;
    int res;

    while (!stop_capture && (res = pcap_next_ex(handle, &header, &data)) >= 0) {
        if (res == 0) continue; 
        process_packet(header, data,
                       dumper_h1, dumper_h2, dumper_h3, dumper_h4);
    }

    printf("\nStopping capture...\n");

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
