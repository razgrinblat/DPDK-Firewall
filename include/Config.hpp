#pragma once
#include <MacAddress.h>
#include <IpAddress.h>

class Config
{
public:
    //NETWORK CONFIGURATION
    static constexpr auto MAX_RECEIVE_BURST = 128;
    static constexpr auto MBUF_POOL_SIZE = 16383; // (2^14 - 1)
    static constexpr auto DPDK_DEVICE_1 = 0;
    static constexpr auto DPDK_DEVICE_2 = 1;
    static constexpr auto DEFAULT_PACKET_SIZE = 100; // in bytes
    static constexpr auto MAX_PORT_NUMBER = 65535;
    static constexpr auto MIN_DYNAMIC_PORT = 49152;
    static constexpr auto MAX_IPV4_OCTET_NUMBER = 255;
    static constexpr auto IP_OCTETS = 4;
    static constexpr auto HTTP_PORT = 80;
    static constexpr auto FTP_PORT = 21;
    static constexpr auto PREALLOCATE_SESSION_TABLE_SIZE = MAX_PORT_NUMBER - MIN_DYNAMIC_PORT + 1; // 16,384 max active sessions
    static constexpr auto DEFAULT_TTL = 64;
    static constexpr auto DEFAULT_MAX_CONTENT_LENGTH = 100*1024; // 100KB for max http payload or ftp file

    //RULES FILE PATH
    static auto constexpr IP_RULES_PATH = "/tmp/tmp.CcQ3HkWRG0/DPDK-Firewall/resources/firewall_rules.json";
    static auto constexpr HTTP_RULES_PATH = "/tmp/tmp.CcQ3HkWRG0/DPDK-Firewall/resources/http_rules.json";
    static auto constexpr FTP_RULES_PATH = "/tmp/tmp.CcQ3HkWRG0/DPDK-Firewall/resources/ftp_rules.json";

    //WEBSOCKET
    static auto constexpr WEBSOCKET_PATH = "ws://172.20.10.2:8080/firewall";
    static auto constexpr WEBSOCKET_SENDING_TIME_IDLE = 1500; // ms

    //ARP CONFIGURATION
    static constexpr auto ARP_REQUEST_OPCODE = 256;
    static constexpr auto MAX_RETRIES = 4; // Maximum number of ARP request retries
    static constexpr auto SLEEP_DURATION = 500; // 500 ms between retries
    static constexpr auto CLEANUP_ARP_ENTRY_TIME = 10; //seconds
    static constexpr auto MAX_IDLE_ARP_TIME = 60; //seconds
    static constexpr auto MAX_ARP_CACHE_SIZE = 1000; // max cache size of 1000 entries

    //DHCP CONFIGURATION
    static constexpr auto DHCP_SERVER_PORT = 67;
    static constexpr auto DHCP_CLIENT_PORT = 68;
    static constexpr uint32_t DHCP_LEASE_TIME = 3600; // sec
    static inline const pcpp::IPv4Address DNS_SERVER{"8.8.8.8"};
    static inline const pcpp::IPv4Address LAN_SUBNET_MASK{"255.255.255.0"};
    static constexpr auto DHCP_IDLE_TIMEOUT = 10; // sec
    static constexpr auto DHCP_CLEANUP_THREAD_INTERVAL = 60; //sec

    //SESSIONS
    static constexpr auto MAX_IDLE_SESSION_TIME = 10; //seconds
    static constexpr auto CLEANUP_IDLE_SESSIONS_TIME = 3; //seconds


    //THREAD MANAGEMENT
    static constexpr auto CORES_TO_USE = 4;

    //IP ADDRESSES
    static inline const pcpp::IPv4Address DPDK_DEVICE1_IP{"192.168.1.10"};
    static inline const pcpp::IPv4Address DPDK_DEVICE2_IP{"192.168.1.22"}; // "192.168.1.22" or "172.20.10.8" in HOTSPOT
    static inline const pcpp::IPv4Address ROUTER_IP{"192.168.1.1"}; // 192.168.1.1 or 172.20.10.1 in HOTSPOT
    static inline const pcpp::IPv4Address BROADCAST_IP{"255.255.255.255"};

    //SUBNET MASK
    static inline const pcpp::IPv4Address SUBNET_MASK{"255.255.255.0"}; //255.255.255.0 or 255.255.255.240 in HOTSPOT

    //MAC ADDRESSES
    static inline const pcpp::MacAddress ROUTER_MAC_ADDRESS{"b4:ee:b4:a9:f7:e1"}; // "b4:ee:b4:a9:f7:e1" or "fa:87:f1:1a:09:64" in HOTSPOT
    static inline const pcpp::MacAddress BROADCAST_MAC_ADDRESS{"ff:ff:ff:ff:ff:ff"};
    static inline const pcpp::MacAddress DPDK_DEVICE1_MAC_ADDRESS{"08:00:27:b4:8e:4a"};
    static inline const pcpp::MacAddress DPDK_DEVICE2_MAC_ADDRESS{"08:00:27:9c:49:2f"};
};