#pragma once
#include <ArpLayer.h>
#include <unordered_map>
#include <Packet.h>
#include <EthLayer.h>
#include <iostream>
#include <IPv4Layer.h>
#include <iomanip>
#include <shared_mutex>

#include "Config.hpp"

class ClientsManager
{

private:
    std::unordered_map<std::string,pcpp::MacAddress> _clients; // client IP to Mac
    std::shared_mutex _clients_mutex;

    void addNewClient(const std::string& src_ip, const pcpp::MacAddress& src_mac);

    ClientsManager() = default;

public:
    ~ClientsManager() = default;
    ClientsManager(const ClientsManager&) = delete;
    ClientsManager& operator=(const ClientsManager&) = delete;
    static ClientsManager& getInstance();


    void processClientPacket(const pcpp::Packet& packet);
    pcpp::MacAddress getClientMacAddress(const pcpp::IPv4Address& client_ip);
    uint16_t getClientID(const pcpp::IPv4Address& client_ip);

    void printClientsTable();

};