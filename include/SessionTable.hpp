#pragma once
#include <IpAddress.h>
#include <unordered_map>
#include <LRUList.h>
#include <memory>
#include <chrono>
#include <shared_mutex>
#include <atomic>
#include <thread>
#include <iomanip>
#include <Packet.h>
#include "PortAllocator.hpp"
#include "WebSocketClient.hpp"
#include "json/json.h"
#include "TcpCommonTypes.hpp"
#include "TcpStateMachine.hpp"

class SessionTable
{
public:

    using TcpState = TCP_COMMON_TYPES::TcpState;
    using Protocol = TCP_COMMON_TYPES::Protocol;

    struct Session
    {
        bool isAllowed;
        Protocol protocol;
        TcpState current_state;
        pcpp::IPv4Address source_ip;
        pcpp::IPv4Address dst_ip;
        uint16_t source_port;
        uint16_t dst_port;
        std::chrono::steady_clock::time_point last_active_time;
        uint16_t firewall_port;
        std::unique_ptr<TcpStateClass> state_object;

        uint32_t received_packet_count;
        uint32_t sent_packet_count;
        double avg_packet_size;

        Session(Protocol protocol, const pcpp::IPv4Address& src_ip, const pcpp::IPv4Address& dst_ip,
                uint16_t src_port, uint16_t dst_port, TcpState state);
    };

    static SessionTable& getInstance();
    ~SessionTable();

    bool isSessionExists(uint32_t session_hash);
    void addNewSession(uint32_t session_hash, std::unique_ptr<Session> session, TcpState state, uint32_t packet_size, TcpSessionHandler* context = nullptr);
    void updateSession(uint32_t session_hash, TcpState new_state, uint32_t packet_size, bool is_outbound, TcpSessionHandler* context = nullptr);
    Session* getSession(uint32_t session_hash);
    uint16_t getFirewallPort(uint32_t session_hash);
    bool isAllowed(uint32_t session_hash);
    void blockSession(uint32_t session_hash);
    void printSessionCache();
    void sendTableToBackend();

private:
    SessionTable();
    void cleanUpIdleSessions();
    void runCleanUpThread();
    double calculateAvgPacketSize(double current_avg, uint32_t sent, uint32_t recv, uint32_t packet_size);

    std::unordered_map<uint32_t, std::unique_ptr<Session>> _session_cache;
    pcpp::LRUList<uint32_t> _lru_list;
    std::shared_mutex _cache_mutex;
    std::atomic<bool> _stop_flag;
    std::thread _clean_up_thread;
    PortAllocator& _port_allocator;
    WebSocketClient& _ws_client;
};