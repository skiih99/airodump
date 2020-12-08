#include "airodump.h"

int main(int argc, char* argv[]) {

    if  (argc != 2) {
        usage();
        return -1;
    }
    beacon_data_cnt = 0;
    probe_data_cnt = 0;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    if (handle == nullptr) {
        fprintf(stderr, "Device open error! %s return nullptr : %s\n", dev, errbuf);
        return -1;
    }

    airodump_process(handle);

    pcap_close(handle);
    
    return 0;
}