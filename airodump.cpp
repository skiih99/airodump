#include "airodump.h"

void usage() {
    printf("syntax : airodump <interface>\n");
	printf("sample : airodump wlan1\"\n");
}

void airodump_process(pcap_t* handle) {
    struct beacon_data bdata[100];
    struct probe_data pdata[100];

    uint8_t cur_essid[200];
    uint8_t cur_bssid[6];
    uint8_t cur_station[6];

    while(1) {
        struct pcap_pkthdr* header;
        uint8_t* pkt;

        int res = pcap_next_ex(handle, &header, (const u_char **)&pkt);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            fprintf(stderr, "pcap_next_ex return error! %d(%s).\n", res, pcap_geterr(handle));
            break;
        }

        struct ieee80211_radiotap_header* radiohdr;
        struct ieee80211_frame* macframe;

        radiohdr = (struct ieee80211_radiotap_header*)pkt;
        int rhdr_len = radiohdr->it_len;
        macframe = (struct ieee80211_frame*)(pkt + rhdr_len);
        int check_fromto = check_flag(macframe->flag);
        if (check_fromto == 0) memcpy(cur_bssid, macframe->addr3, 6);
        else if (check_fromto == 1) memcpy(cur_bssid, macframe->addr1, 6);
        else if (check_fromto == 2) memcpy(cur_bssid, macframe->addr2, 6);
        else for (int i = 0; i < 6; i++) cur_bssid[i] = 0xFF;

        // management frame => Beacon frame
        if(macframe->type == 0x80) {
            uint8_t* tag_param = pkt + rhdr_len + sizeof(struct ieee80211_frame) + fixed_param_len;
            int cur_essid_len = (int)tag_param[1];
            memcpy(cur_essid, tag_param + 2, cur_essid_len);
            bool flag = false;
            for (int i = 0; i < beacon_data_cnt; i++) {
                if ((cur_essid_len == bdata[i].essid_len) && !memcmp(bdata[i].bssid, cur_bssid, 6) && !memcmp(bdata[i].essid, cur_essid, cur_essid_len)) {
                    bdata[i].beacons++;
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                memcpy(bdata[beacon_data_cnt].bssid, cur_bssid, 6);
                memcpy(bdata[beacon_data_cnt].essid, cur_essid, cur_essid_len);
                bdata[beacon_data_cnt].essid_len = cur_essid_len;
                bdata[beacon_data_cnt].beacons = 1;
                bdata[beacon_data_cnt].data = 0;
                beacon_data_cnt++;
            }
        }

        // management frame => probe request
        else if(macframe->type == 0x40) {
            if (check_fromto == 2) memcpy(cur_station, macframe->addr1, 6);
            else memcpy(cur_station, macframe->addr2, 6);
            uint8_t* tag_param = pkt + rhdr_len + sizeof(struct ieee80211_frame);
            int cur_probe_len = (int)tag_param[1];

            bool flag = false;
            for (int i = 0; i < probe_data_cnt; i++) {
                if(!memcmp(pdata[i].bssid, cur_bssid, 6) && !memcmp(pdata[i].station, cur_station, 6)) {
                    pdata[i].frames++;
                    if (cur_probe_len > 0) {
                        pdata[i].probe_len = cur_probe_len;
                        memcpy(pdata[i].probe, tag_param + 2, cur_probe_len);
                    }
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                memcpy(pdata[probe_data_cnt].bssid, cur_bssid, 6);
                memcpy(pdata[probe_data_cnt].station, cur_station, 6);
                pdata[probe_data_cnt].probe_len = cur_probe_len;
                memcpy(pdata[probe_data_cnt].probe, tag_param + 2, cur_probe_len);
                pdata[probe_data_cnt].frames = 1;
                probe_data_cnt++;
            }
        }

        // management frame => probe response
        else if(macframe->type == 0x50) {
            uint8_t* tag_param = pkt + rhdr_len + sizeof(struct ieee80211_frame) + fixed_param_len;
            int cur_essid_len = (int)tag_param[1];
            memcpy(cur_essid, tag_param + 2, cur_essid_len);

            bool flag = false;
            for (int i = 0; i < beacon_data_cnt; i++) {
                if ((cur_essid_len == bdata[i].essid_len) && !memcmp(bdata[i].bssid, cur_bssid, 6) && !memcmp(bdata[i].essid, cur_essid, cur_essid_len)) {
                    flag = true;
                    break;
                }
            }

            if (!flag) {
                memcpy(bdata[beacon_data_cnt].bssid, cur_bssid, 6);
                memcpy(bdata[beacon_data_cnt].essid, cur_essid, cur_essid_len);
                bdata[beacon_data_cnt].essid_len = cur_essid_len;
                bdata[beacon_data_cnt].beacons = 0;
                bdata[beacon_data_cnt].data = 0;
                beacon_data_cnt++;
            }


        }

        else if((macframe->type & 0x08) >> 3) { // data frame
            if (check_fromto == 2) memcpy(cur_station, macframe->addr1, 6);
            else memcpy(cur_station, macframe->addr2, 6);

            // macframe->type & 0x40 >> 6 == 1 => no data : data++ X
            // else data++

            // loop for pdata. 


        }

        


    }
}

int check_flag(uint8_t flag) {
    return (int)(flag & 0x03); // ././././././From/To
}