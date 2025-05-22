#pragma once
#include "Config.hpp"
#include <unordered_map>
#include <random>
#include <shared_mutex>
#include <json/json.h>
#include <WebSocketClient.hpp>
#include <iomanip>
#include <iostream>

class PortAllocator
{

private:
    std::random_device _seed;
    std::mt19937 _generator;
    std::shared_mutex _table_mutex;
    uint16_t _free_count;
    std::unordered_map<uint16_t,std::pair<pcpp::IPv4Address,uint16_t>> _pat_table; // firewall port to client_ip, client_port
    std::array<uint16_t,Config::PREALLOCATE_SESSION_TABLE_SIZE> _free_ports_pool;

    PortAllocator();
    uint16_t generatePoolIndex();

public:
    PortAllocator(const PortAllocator&) = delete;
    PortAllocator& operator=(const PortAllocator&) = delete;
    ~PortAllocator() = default;
    static PortAllocator& getInstance();

    std::optional<std::pair<pcpp::IPv4Address,uint16_t>> getClientIpAndPort(uint16_t firewall_port);
    uint16_t allocatePort(const pcpp::IPv4Address& client_ip, uint16_t client_port);
    void releasePort(uint16_t port);
    void printPortsTable();
    void sendPortsToBackend();

};
