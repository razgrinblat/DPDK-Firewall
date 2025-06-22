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
#include "FirewallLogger.hpp"

/**
 * @class DhcpServer
 * @brief Implements a singleton DHCP server for handling DHCP messages and lease assignments.
 */
class DhcpServer
{
private:

    /**
     * @struct LeaseEntry
     * @brief Represents a DHCP lease entry with IP address and lease timing info.
     */
    struct LeaseEntry
    {
        pcpp::IPv4Address offered_ip_address; ///< IP address offered to the client
        std::chrono::steady_clock::time_point expiration; ///< Lease start time
        uint32_t expiry_time; ///< Lease duration in seconds

        /**
         * @brief Constructor to initialize lease entry.
         * @param ipv4_addr IP address offered
         * @param expiry_time Lease time in seconds
         */
        LeaseEntry(const pcpp::IPv4Address& ipv4_addr, const uint32_t expiry_time) :
        offered_ip_address(ipv4_addr), expiration(std::chrono::steady_clock::now()), expiry_time(expiry_time)
     {}
    };

    std::deque<pcpp::IPv4Address> _dhcp_pool; ///< Available IP addresses
    std::unordered_map<std::string, LeaseEntry> _lease_map; ///< MAC address to lease entry map
    std::thread _lease_cleanup_thread; ///< Background thread for lease cleanup
    std::mutex _lease_mutex; ///< Mutex for thread-safe lease access
    bool _is_running; ///< Indicates if cleanup thread is running

    /**
     * @brief Private constructor to enforce singleton pattern.
     */
    DhcpServer();

    /**
     * @brief Initializes the DHCP pool based on configured IP range.
     */
    void initializeDhcpPool();

    /**
     * @brief Calculates the time difference between two time points.
     * @param current_time Current time
     * @param dhcp_entry_time Lease start time
     * @return Time difference in seconds
     */
    uint32_t getTimeDifference(const std::chrono::steady_clock::time_point &current_time,
                               const std::chrono::steady_clock::time_point &dhcp_entry_time);

    /**
     * @brief Cleans up expired entries from the lease map.
     */
    void cleanUpLeaseMap();

    /**
     * @brief Starts the cleanup thread to remove expired leases periodically.
     */
    void runCleanUpThread();

    /**
     * @brief Adds a new DHCP lease entry.
     * @param client_mac_address Client MAC address
     * @param offered_ip Offered IP address
     * @param expiry_time Lease duration in seconds
     */
    void addNewDhcpEntry(const pcpp::MacAddress& client_mac_address, const pcpp::IPv4Address& offered_ip, uint32_t expiry_time);

    /**
     * @brief Searches for a requested IP in the DHCP pool.
     * @param requested_ip IP requested by client
     * @return Iterator to the IP if found, or end iterator
     */
    std::deque<pcpp::IPv4Address>::iterator findRequestedIp(const pcpp::IPv4Address& requested_ip);

    /**
     * @brief Builds a complete DHCP packet with layers for Ethernet, IPv4, UDP, and DHCP.
     * @param client_mac_address MAC address of the client
     * @param transaction_id DHCP transaction ID
     * @param dhcp_type DHCP message type
     * @return Fully constructed DHCP packet
     */
    pcpp::Packet buildDhcpPacket(const pcpp::MacAddress& client_mac_address, uint32_t transaction_id, pcpp::DhcpMessageType dhcp_type);

    /**
     * @brief Adds DHCP options to the DHCP layer.
     * @param dhcp_layer DHCP layer to modify
     */
    void addDhcpOptions(pcpp::DhcpLayer& dhcp_layer);

    /**
     * @brief Sends a DHCP packet to the client.
     * @param offered_ip IP address to assign
     * @param dhcp_layer Original request layer for context
     * @param dhcp_type DHCP message type (e.g. ACK)
     * @return True if successfully sent
     */
    bool sendDhcpPacket(const pcpp::IPv4Address &offered_ip, const pcpp::DhcpLayer &dhcp_layer, pcpp::DhcpMessageType dhcp_type);

    /**
     * @brief Removes a DHCP entry from the lease map and returns IP to pool.
     * @param client_mac_address MAC address
     * @param used_ip Previously assigned IP
     */
    void removeDhcpEntry(const std::string& client_mac_address, const pcpp::IPv4Address& used_ip);

    /**
     * @brief Sends a DHCP NAK message when a request cannot be granted.
     * @param request_dhcp_layer DHCP layer from the client request
     */
    void sendDhcpNak(const pcpp::DhcpLayer& request_dhcp_layer);

    /**
     * @brief Handles DHCPDISCOVER message.
     * @param dhcp_layer DHCP layer from client
     */
    void handleDhcpDiscover(const pcpp::DhcpLayer& dhcp_layer);

    /**
     * @brief Handles DHCPREQUEST message and delegates processing.
     * @param dhcp_layer DHCP layer from client
     */
    void handleDhcpRequest(const pcpp::DhcpLayer& dhcp_layer);

    /**
     * @brief Handles DHCPREQUEST for already-leased IPs.
     * @param client_mac_address MAC address
     * @param requested_ip IP requested
     * @param dhcp_layer DHCP request layer
     * @param lease_entry Existing lease entry
     */
    void handleLeasedDhcpRequest(const std::string& client_mac_address, const pcpp::IPv4Address& requested_ip,
                                 const pcpp::DhcpLayer& dhcp_layer, LeaseEntry& lease_entry);

    /**
     * @brief Handles DHCPREQUEST for IPs not yet leased.
     * @param client_mac_address MAC address
     * @param requested_ip Requested IP
     * @param dhcp_layer DHCP request layer
     */
    void handleUnLeasedDhcpRequest(const std::string& client_mac_address, const pcpp::IPv4Address& requested_ip,
                                   const pcpp::DhcpLayer& dhcp_layer);

    /**
     * @brief Handles DHCPRELEASE messages from clients.
     * @param dhcp_layer DHCP layer from release message
     */
    void handleDhcpRelease(const pcpp::DhcpLayer& dhcp_layer);

public:

    DhcpServer(const DhcpServer&) = delete; ///< Deleted copy constructor
    DhcpServer& operator=(const DhcpServer&) = delete; ///< Deleted assignment operator

    /**
     * @brief Destructor. Ensures cleanup thread is stopped.
     */
    ~DhcpServer();

    /**
     * @brief Access singleton instance of the DHCP server.
     * @return Reference to the single DhcpServer instance
     */
    static DhcpServer& getInstance();

    /**
     * @brief Entry point for handling any DHCP client packet.
     * @param dhcp_layer DHCP packet received from client
     */
    void DhcpClientHandler(const pcpp::DhcpLayer& dhcp_layer);
};
