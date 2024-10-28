#pragma once
#include <ArpLayer.h>
#include <unordered_map>
#include "Config.hpp"
#include <EthLayer.h>
#include <iostream>
#include <Packet.h>
#include <DpdkDeviceList.h>


class ArpHandler
{
private:
    std::unordered_map<std::string,std::string> _cache; // IP,MAC
    std::vector<std::string> _last_requests;

public:
    ArpHandler();
    ~ArpHandler();
    void handleArpRequestFromClient(const pcpp::ArpLayer& arp_layer);
    void handleArpRequest(const pcpp::ArpLayer& arp_layer);
    void sendArpResponse(const pcpp::IPv4Address& target_ip, const pcpp::MacAddress& target_mac,
                         const pcpp::IPv4Address& requester_ip, const pcpp::MacAddress& requester_mac, uint16_t device_id);
    void handleArpResponseToClient();
    bool lookUp();
    void updateCache();
};

