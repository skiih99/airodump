#include "airodump.h"

void usage() {
    printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\"\n");
}

void airodump_process(pcap_t* handle) {
    while(1) {
        struct pcap_pkthdr* header;
        uint8_t* rcv_packet;

        int res = pcap_next_ex(handle, &header, (const u_char **)&rcv_packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }

    }
}