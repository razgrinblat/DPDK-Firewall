#include "ClientsManager.hpp"

void ClientsManager::addNewClient(const std::string& src_mac, const std::string& src_ip)
{
    _clients[src_ip] = src_mac;
    std::cout << "Client with IP: " << src_ip << " and MAC: " << src_mac << " joined to the Firewall!" <<std::endl;
}

ClientsManager & ClientsManager::getInstance()
{
    static ClientsManager instance;
    return instance;
}

void ClientsManager::processClientPacket(const pcpp::Packet& packet)
{
    const pcpp::IPv4Layer* ipv4_layer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) return; //No IPv4 layer, cannot process the packet

    const std::string src_ip = ipv4_layer->getSrcIPAddress().toString();

    const pcpp::EthLayer* eth_layer = packet.getLayerOfType<pcpp::EthLayer>();
    const std::string src_mac = eth_layer->getSourceMac().toString();

    if ( src_ip != Config::DPDK_DEVICE2_IP.toString() && _clients.find(src_ip) == _clients.end())
    {
        addNewClient(src_mac, src_ip);
    }
}

void ClientsManager::printClientsTable()
{
    std::cout << "Clients Table:" << std::endl;
    std::cout << std::left << std::setw(20) << "IP Address" << "MAC Address" << std::endl;
    std::cout << "------------------------------" << std::endl;

    for (const auto&[first, second] : _clients)
    {
        std::cout << std::left << std::setw(20) << first << second << std::endl;
    }
}
