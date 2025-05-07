#pragma once
#include <ArpLayer.h>
#include <unordered_map>
#include "Config.hpp"
#include <EthLayer.h>
#include <Packet.h>
#include <DpdkDeviceList.h>
#include <IPv4Layer.h>
#include <unordered_set>
#include <mutex>
#include <condition_variable>
#include <thread>
#include "PacketStats.hpp"
#include <atomic>
#include "FirewallLogger.hpp"

class ArpHandler
{
private:
    struct ArpCacheEntry
    {
        std::string mac_addr;
        std::chrono::steady_clock::time_point last_active_time;
    };

    std::unordered_map<std::string, ArpCacheEntry> _cache; // IP to MAC cache
    std::unordered_set<std::string> _unresolved_arp_requests; // Track IPs with pending unresolved ARP requests
    std::mutex _cache_mutex; // Mutex for cache access
    std::condition_variable _arp_condition;// Condition variable for ARP response
    std::atomic<bool> _stop_flag; //threads stop flag
    std::vector<std::thread> _threads; // requests thread pool
    std::thread _clean_up_thread;
    PacketStats& _packet_stats;
    uint16_t _current_entries_counter;

    ArpHandler();
    bool addNewArpEntry(const std::string& ip_addr, const std::string& mac_addr);
    void stopThreads();
    bool isRequestAlreadyPending(const pcpp::IPv4Address& target_ip);
    void threadHandler(const pcpp::IPv4Address& target_ip); //thread handler for sending ARP requests
    void sendArpRequestPacket(const pcpp::IPv4Address& target_ip) const;
    void removePendingRequest(const pcpp::IPv4Address& target_ip);

    void handleReceivedArpRequest(const pcpp::ArpLayer& arp_layer); //handle Received ARP Requests in TxReceivedThread
    void handleReceivedArpResponse(const pcpp::ArpLayer& arp_layer); //handle Received ARP Responses in TxReceivedThread
    uint16_t getArpIdleTimeInSeconds(const std::chrono::steady_clock::time_point& current_time,
        const std::chrono::steady_clock::time_point& arp_entry_time);
    void cleanUpArpCache();
    void runCleanUpThread();

public:

    ~ArpHandler();
    ArpHandler(const ArpHandler&) = delete;
    ArpHandler& operator=(const ArpHandler&) = delete;
    static ArpHandler& getInstance();

    void sendArpResponsePacket(const pcpp::IPv4Address& target_ip, const pcpp::MacAddress& target_mac, uint16_t sender_device_id) const;
    void handleReceivedArpPacket(const pcpp::ArpLayer& arp_layer);
    void sendArpRequest(const pcpp::IPv4Address& target_ip); //send an ARP request in a separate thread
    pcpp::MacAddress getMacAddress(const pcpp::IPv4Address& ip);
    void printArpCache();
    void sendArpTableToBackend();
};