#pragma once
#include <ArpLayer.h>
#include <unordered_map>
#include "Config.hpp"
#include <EthLayer.h>
#include <iostream>
#include <Packet.h>
#include <DpdkDeviceList.h>
#include <IPv4Layer.h>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "PacketStats.hpp"

class ArpHandler
{
private:
    std::unordered_map<std::string,std::string> _cache;              // IP to MAC cache
    std::unordered_set<std::string> _pending_arp_requests;              // Track IPs with pending ARP requests
    std::mutex _cache_mutex;                                          // Mutex for cache access
    std::condition_variable _arp_response_received;                    // Condition variable for ARP response

    ArpHandler() = default;

public:

    ~ArpHandler();
    ArpHandler(const ArpHandler&) = delete;
    ArpHandler& operator=(const ArpHandler&) = delete;
    static ArpHandler& getInstance();

    void handleReceivedArpRequest(const pcpp::ArpLayer& arp_layer); //handle Received ARP Requests in TxReceivedThread
    void handleReceivedArpResponse(const pcpp::ArpLayer& arp_layer); //handle Received ARP Responses in TxReceivedThread
    void handleReceivedArpPacket(const pcpp::ArpLayer& arp_layer);
    void sendArpRequest(const pcpp::IPv4Address& target_ip); //send an ARP request in a separate thread
    pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& ip);
    void printArpCache();
    void sendArpResponse(const pcpp::IPv4Address& target_ip, const pcpp::MacAddress& target_mac,
                         const pcpp::IPv4Address& requester_ip, const pcpp::MacAddress& requester_mac, uint16_t device_id);
};

