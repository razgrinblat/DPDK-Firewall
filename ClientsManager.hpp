#pragma once
#include <ArpLayer.h>
#include <unordered_map>
#include <Packet.h>
#include <EthLayer.h>
#include <iostream>
#include <IPv4Layer.h>
#include <iomanip>
#include "Config.hpp"

class ClientsManager
{

private:
    std::unordered_map<std::string, std::string> _clients; // client IP and Mac
    void addNewClient(const std::string& src_mac, const std::string& src_ip);

    ClientsManager() = default;

public:
    ~ClientsManager() = default;
    ClientsManager(const ClientsManager&) = delete;
    ClientsManager& operator=(const ClientsManager&) = delete;
    static ClientsManager& getInstance();


    void processClientPacket(const pcpp::Packet& packet);
    void printClientsTable();

};