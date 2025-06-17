#pragma once
#include <DhcpLayer.h>
#include <queue>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <unordered_set>
#include "Config.hpp"
#include <thread>
#include <mutex>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <UdpLayer.h>
#include <DpdkDeviceList.h>

class DhcpServer
{

private:

    struct LeaseEntry
    {
        pcpp::IPv4Address offered_ip_address;
        std::chrono::steady_clock::time_point expiration;
        uint32_t expiry_time;

        LeaseEntry(const pcpp::IPv4Address& ipv4_addr, const uint32_t expiry_time):
        offered_ip_address(ipv4_addr), expiration(std::chrono::steady_clock::now()),
        expiry_time(expiry_time)
        {}
    };

    std::deque<pcpp::IPv4Address> _dhcp_pool;
    std::unordered_map<std::string, LeaseEntry> _lease_map;
    std::thread _lease_cleanup_thread;
    std::mutex _lease_mutex;
    bool _is_running;

    DhcpServer();

    void initializeDhcpPool();

    uint32_t getTimeDifference(const std::chrono::steady_clock::time_point &current_time,
    const std::chrono::steady_clock::time_point &dhcp_entry_time);

    void cleanUpLeaseMap();

    void runCleanUpThread();

    void addNewDhcpEntry(const pcpp::MacAddress& client_mac_address, const pcpp::IPv4Address& offered_ip, uint32_t expiry_time);

    std::deque<pcpp::IPv4Address>::iterator findRequestedIp(const pcpp::IPv4Address& requested_ip);

    bool sendDhcpOffer(const pcpp::IPv4Address& offered_ip, const pcpp::DhcpLayer& discover_dhcp_layer);

    bool sendDhcpAck(const pcpp::IPv4Address& offered_ip, const pcpp::DhcpLayer& request_dhcp_layer);

    void removeDhcpEntry(const std::string& client_mac_address, const pcpp::IPv4Address& used_ip);

    void sendDhcpNak(const pcpp::DhcpLayer& request_dhcp_layer);

    void handleDhcpDiscover(const pcpp::DhcpLayer& dhcp_layer);

    void handleDhcpRequest(const pcpp::DhcpLayer& dhcp_layer);

    void handleDhcpRealse(const pcpp::DhcpLayer& dhcp_layer);

    bool sendDhcpPacket( pcpp::Packet& dhcp_packet);


public:

    DhcpServer(const DhcpServer&) = delete;
    DhcpServer& operator=(const DhcpServer&) = delete;
    ~DhcpServer();

    static DhcpServer& getInstance();

    void DhcpClientHandler(const pcpp::DhcpLayer& dhcp_layer);

};
