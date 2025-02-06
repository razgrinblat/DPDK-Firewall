#pragma once
#include <IpAddress.h>
#include <unordered_map>
#include <LRUList.h>
#include <memory>
#include <chrono>
#include <shared_mutex>
#include "Config.hpp"
#include <atomic>
#include <thread>
#include <iostream>
#include <iomanip>
#include <Packet.h>
#include "PortAllocator.hpp"

class SessionTable
{
public:
    enum TcpState {
        SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT1, FIN_WAIT2,
        CLOSE_WAIT, TIME_WAIT, LAST_ACK, UNKNOWN, UDP
    };

    enum Protocol{TCP_PROTOCOL, UDP_PROTOCOL};

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

        Session(const Protocol protocol, const pcpp::IPv4Address& src_ip, const pcpp::IPv4Address& dst_ip,
                   const uint16_t src_port, const uint16_t dst_port,
                   const TcpState state)
            : isAllowed(true), protocol(protocol), current_state(state), source_ip(src_ip), dst_ip(dst_ip),
              source_port(src_port), dst_port(dst_port), firewall_port(0) {}
    };

    ~SessionTable();
    SessionTable(const SessionTable&) = delete;
    SessionTable& operator=(const SessionTable&) = delete;
    static SessionTable& getInstance();

    bool isSessionExists(uint32_t session_hash);
    void addNewSession(uint32_t session_hash, std::unique_ptr<Session> session, const TcpState& current_state = UNKNOWN);
    const TcpState& getCurrentState(uint32_t session_hash);
    uint16_t getFirewallPort(uint32_t session_hash);
    void updateSession(uint32_t session_hash, const TcpState& new_state = UNKNOWN);
    bool isAllowed(uint32_t session_hash);
    void blockSession(uint32_t session_hash);
    void printSessionCache();


private:
    std::unordered_map<uint32_t,std::unique_ptr<Session>> _session_cache;
    pcpp::LRUList<uint32_t> _lru_list;
    std::shared_mutex _cache_mutex;
    std::atomic<bool> _stop_flag;
    std::thread _clean_up_thread;
    PortAllocator& _port_allocator;

    SessionTable();
    void cleanUpIdleSessions();
    void runCleanUpThread();

};

