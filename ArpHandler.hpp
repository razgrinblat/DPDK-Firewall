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
#include <atomic>

class ArpHandler
{
private:
    std::unordered_map<std::string,std::string> _cache;              // IP to MAC cache
    std::unordered_set<std::string> _unresolved_arp_requests;              // Track IPs with pending unresolved ARP requests
    std::mutex _cache_mutex;                                          // Mutex for cache access
    std::condition_variable _arp_response_received;// Condition variable for ARP response
    std::atomic<bool> _stop_flag; //threads stop flag
    std::vector<std::thread> _threads; //thread pool

    ArpHandler();
    void stopThreads();
    void sendArpResponse(const pcpp::IPv4Address& target_ip, const pcpp::MacAddress& target_mac);
    bool isRequestAlreadyPending(const pcpp::IPv4Address& target_ip);
    void threadHandler(const pcpp::IPv4Address& target_ip); //thread handler for sending ARP requests
    bool sendArpRequestPacket(const pcpp::IPv4Address& target_ip);
    void removePendingRequest(const pcpp::IPv4Address& target_ip);

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
};