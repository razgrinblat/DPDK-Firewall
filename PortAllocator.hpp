#pragma once
#include <bitset>
#include "Config.hpp"
#include "unordered_map"

class PortAllocator
{

private:
    static auto constexpr PORT_RANGE = Config::MAX_PORT_NUMBER - Config::MIN_DYNAMIC_PORT + 1;

    std::bitset<PORT_RANGE> _firewall_ports;
    std::unordered_map<uint16_t,std::pair<pcpp::IPv4Address,uint16_t>> _ports_in_use; // firewall port to client_ip, client_port

public:
    uint16_t allocatePort();
    void releasePort();


};
