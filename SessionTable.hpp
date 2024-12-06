#pragma once
#include <IpAddress.h>
#include <unordered_map>
#include <LRUList.h>
#include <memory>
#include <chrono>
#include <mutex>
#include "Config.hpp"
#include <atomic>
#include <thread>
#include <iostream>
#include <iomanip>

enum TcpState {
    SYN_SENT, SYN_RECEIVED, ESTABLISHED, FIN_WAIT1, FIN_WAIT2,
    CLOSE_WAIT,  TIME_WAIT, UNKNOWN
};
struct TcpSession
{
    TcpState current_state;
    uint32_t current_ack;
    uint32_t current_seq;
    pcpp::IPv4Address source_ip;
    pcpp::IPv4Address dst_ip;
    uint16_t source_port;
    uint16_t dst_port;
    std::chrono::time_point<std::chrono::steady_clock> last_active_time;
};

class SessionTable
{
private:
    std::unordered_map<uint32_t,std::unique_ptr<TcpSession>> _session_cache;
    pcpp::LRUList<uint32_t> _lru_list;
    std::mutex _cache_mutex;
    std::atomic<bool> _stop_flag;
    std::thread _clean_up_thread;

    SessionTable();
    void cleanUpIdleSessions();
    void runCleanUpThread();

public:
    ~SessionTable();
    SessionTable(const SessionTable&) = delete;
    SessionTable& operator=(const SessionTable&) = delete;
    static SessionTable& getInstance();

    bool isSessionExists(uint32_t session_hash);
    bool addNewSession(uint32_t session_hash, std::unique_ptr<TcpSession> session, const TcpState& current_state);
    TcpState& getCurrentState(uint32_t session_hash);
    void updateSession(uint32_t session_hash, const TcpState& new_state);
    void printSessionCache();



};

