#include "ClientsManager.hpp"

void ClientsManager::processNewIncomingIp(const std::string& src_ip, const pcpp::MacAddress& src_mac)
{
    std::unique_lock write_lock(_clients_mutex);
    if (_clients_mac.find(src_mac.toString()) != _clients_mac.end()) //client is already exist and changed is ip
    {
        changeClientIp(src_ip, src_mac);
    }
    else
    {
        addNewClient(src_ip, src_mac);
    }
}

void ClientsManager::changeClientIp(const std::string &src_ip, const pcpp::MacAddress &src_mac)
{
    for(const auto& [old_ip, mac] : _clients)
    {
        if (mac == src_mac)
        {
            _clients[old_ip] = src_mac;
            std::cout << "Client with IP: " << old_ip << " and MAC: " << src_mac.toString() << "changed is IP to:"
             << src_ip << std::endl;
        }
    }
}

void ClientsManager::addNewClient(const std::string &src_ip, const pcpp::MacAddress &src_mac)
{
    _clients[src_ip] = src_mac;
    _clients_mac.emplace(src_mac.toString());
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

    const std::string& src_ip = ipv4_layer->getSrcIPAddress().toString();
    const pcpp::MacAddress& src_mac = packet.getLayerOfType<pcpp::EthLayer>()->getSourceMac();

    {
        std::shared_lock read_lock(_clients_mutex);
        if (_clients.find(src_ip) != _clients.end() || ipv4_layer->getSrcIPAddress() == pcpp::IPv4Address::Zero) //broadcast ip
        {
            return;
        }
    }
    processNewIncomingIp(src_ip, src_mac);
}

pcpp::MacAddress ClientsManager::getClientMacAddress(const pcpp::IPv4Address &client_ip)
{
    std::shared_lock read_lock(_clients_mutex);
    if (_clients.find(client_ip.toString()) != _clients.end())
    {
        return _clients[client_ip.toString()];
    }
    return {};
}

void ClientsManager::printClientsTable()
{
    std::shared_lock read_lock(_clients_mutex);
    std::cout << "Clients Table:" << std::endl;
    std::cout << std::left << std::setw(20) << "IP Address" << "MAC Address" << std::endl;
    std::cout << "------------------------------" << std::endl;

    for (const auto&[client_ip, client_mac] : _clients)
    {
        std::cout << std::left << std::setw(20) << client_ip << client_mac << std::endl;
    }
}