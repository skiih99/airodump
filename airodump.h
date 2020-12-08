#pragma once
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>

#define fixed_param_len 12

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        uint8_t it_version;     /* set to 0 */
        uint8_t it_pad;
        uint16_t it_len;         /* entire length */
        uint32_t it_present;     /* fields present */
};

struct ieee80211_mac_frame {
    uint8_t type;
    uint8_t flag;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq;
};

struct beacon_data {
    uint8_t bssid[6];
    int beacons;
    char essid[200];
    int essid_len;
};

struct probe_data {
    uint8_t bssid[6];
    uint8_t station[6];
    char probe[200];
    int probe_len;
};
#pragma pack(pop)

using namespace std;

int beacon_data_cnt;
int probe_data_cnt;
void usage();
void airodump_process(pcap_t* handle);

