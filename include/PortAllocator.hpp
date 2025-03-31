#pragma once
#include "Config.hpp"
#include <unordered_map>
#include <random>
#include <shared_mutex>
#include <iomanip>
#include <iostream>

class PortAllocator
{

private:
    std::random_device _seed;
    std::mt19937 _generator;
    std::shared_mutex _table_mutex;
    std::uniform_int_distribution<uint16_t> _port_range;
    std::unordered_map<uint16_t,std::pair<pcpp::IPv4Address,uint16_t>> _ports_in_use_table; // firewall port to client_ip, client_port

    PortAllocator();
    uint16_t generatePort();

public:
    PortAllocator(const PortAllocator&) = delete;
    PortAllocator& operator=(const PortAllocator&) = delete;
    ~PortAllocator() = default;
    static PortAllocator& getInstance();

    std::optional<std::pair<pcpp::IPv4Address,uint16_t>> getClientIpAndPort(uint16_t firewall_port);
    uint16_t allocatePort(const pcpp::IPv4Address& client_ip, uint16_t client_port);
    void releasePort(uint16_t port);
    void printPortsTable();

};
