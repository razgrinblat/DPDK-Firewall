#include "ClientsManager.hpp"

void ClientsManager::addNewClient(const std::string& src_ip, const pcpp::MacAddress& src_mac)
{
    std::unique_lock writer_lock(_clients_mutex);
    _clients[src_ip] = src_mac;
    std::cout << "Client with IP: " << src_ip << " and MAC: " << src_mac.toString() << " joined to the Firewall!" << std::endl;
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
    const pcpp::MacAddress src_mac = eth_layer->getSourceMac();

    {
        std::shared_lock read_lock(_clients_mutex);
        if (_clients.find(src_ip) != _clients.end() || ipv4_layer->getSrcIPAddress() == pcpp::IPv4Address::Zero)
        {
            return;
        }
    }
    addNewClient(src_ip, src_mac);
}

pcpp::MacAddress ClientsManager::getClientMacAddress(const pcpp::IPv4Address &client_ip)
{
    std::shared_lock lock(_clients_mutex);
    if (_clients.find(client_ip.toString()) != _clients.end())
    {
        return _clients[client_ip.toString()];
    }
    return {};
}

void ClientsManager::printClientsTable()
{
    std::shared_lock lock(_clients_mutex);
    std::cout << "Clients Table:" << std::endl;
    std::cout << std::left << std::setw(20) << "IP Address" << "MAC Address" << std::endl;
    std::cout << "------------------------------" << std::endl;

    for (const auto&[client_ip, client_mac] : _clients)
    {
        std::cout << std::left << std::setw(20) << client_ip << client_mac << std::endl;
    }
}
