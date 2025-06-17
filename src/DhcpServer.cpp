#include "DhcpServer.hpp"

DhcpServer::DhcpServer() : _is_running(true)
{
    initializeDhcpPool();
    _lease_cleanup_thread = std::thread(&DhcpServer::runCleanUpThread,this);
}

void DhcpServer::initializeDhcpPool()
{
    for (uint16_t i = 1; i < Config::MAX_IPV4_OCTET_NUMBER; i++)
    {
        pcpp::IPv4Address ipv4_addr("192.168.1." + std::to_string(i));
        if ( ipv4_addr.toString() == Config::DPDK_DEVICE1_IP.toString()) continue;
        _dhcp_pool.push_back(ipv4_addr);
    }
}

uint32_t DhcpServer::getTimeDifference(const std::chrono::steady_clock::time_point &current_time,
    const std::chrono::steady_clock::time_point &dhcp_entry_time)
{
    return std::chrono::duration_cast<std::chrono::seconds>(current_time - dhcp_entry_time).count();
}

void DhcpServer::cleanUpLeaseMap()
{
    std::lock_guard lock(_lease_mutex);
    const auto current_time = std::chrono::steady_clock::now();
    for (auto it = _lease_map.begin(); it != _lease_map.end();)
    {
        const auto lease_entry = it->second;
        if (getTimeDifference(current_time,it->second.expiration) > lease_entry.expiry_time)
        {
            removeDhcpEntry(it->first,lease_entry.offered_ip_address);
        }
        else {
            ++it;
        }
    }
}

void DhcpServer::runCleanUpThread()
{
    while (_is_running)
    {
        cleanUpLeaseMap();
        std::this_thread::sleep_for(std::chrono::seconds(Config::DHCP_CLEANUP_THREAD_INTERVAL));
    }
}

std::deque<pcpp::IPv4Address>::iterator DhcpServer::findRequestedIp(const pcpp::IPv4Address &requested_ip)
{
    return std::find(_dhcp_pool.begin(), _dhcp_pool.end(), requested_ip);
}

bool DhcpServer::sendDhcpAck(const pcpp::IPv4Address &offered_ip, const pcpp::DhcpLayer &request_dhcp_layer)
{
    pcpp::EthLayer eth_layer(Config::DPDK_DEVICE1_MAC_ADDRESS,request_dhcp_layer.getClientHardwareAddress());

    pcpp::IPv4Layer ipv4_layer(Config::DPDK_DEVICE1_IP,Config::BROADCAST_IP);
    ipv4_layer.getIPv4Header()->timeToLive = Config::DEFAULT_TTL;

    pcpp::UdpLayer udp_layer(Config::DHCP_SERVER_PORT,Config::DHCP_CLIENT_PORT);

    pcpp::DhcpLayer dhcp_layer;
    dhcp_layer.setMessageType(pcpp::DHCP_ACK);
    dhcp_layer.setClientHardwareAddress(request_dhcp_layer.getClientHardwareAddress());
    dhcp_layer.setYourIpAddress(offered_ip);
    dhcp_layer.getDhcpHeader()->transactionID = request_dhcp_layer.getDhcpHeader()->transactionID;

    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_LEASE_TIME,Config::DHCP_LEASE_TIME));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS,Config::DNS_SERVER));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_SUBNET_MASK,Config::LAN_SUBNET_MASK));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_ROUTERS,Config::DPDK_DEVICE1_IP));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_END,nullptr,0));

    pcpp::Packet packet(Config::DEFAULT_PACKET_SIZE);
    packet.addLayer(&eth_layer);
    packet.addLayer(&ipv4_layer);
    packet.addLayer(&udp_layer);
    packet.addLayer(&dhcp_layer);
    packet.computeCalculateFields();

    const auto device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_1);
    if (device1->sendPacket(packet))
    {
        return true;
    }
    return false;
}

void DhcpServer::removeDhcpEntry(const std::string& client_mac_address, const pcpp::IPv4Address& used_ip)
{
    _dhcp_pool.push_back(used_ip);
    _lease_map.erase(client_mac_address);
}

void DhcpServer::sendDhcpNak(const pcpp::DhcpLayer& request_dhcp_layer)
{
    pcpp::EthLayer eth_layer(Config::DPDK_DEVICE1_MAC_ADDRESS,request_dhcp_layer.getClientHardwareAddress());

    pcpp::IPv4Layer ipv4_layer(Config::DPDK_DEVICE1_IP,Config::BROADCAST_IP);
    ipv4_layer.getIPv4Header()->timeToLive = Config::DEFAULT_TTL;

    pcpp::UdpLayer udp_layer(Config::DHCP_SERVER_PORT,Config::DHCP_CLIENT_PORT);

    pcpp::DhcpLayer dhcp_layer;
    dhcp_layer.setMessageType(pcpp::DHCP_NAK);
    dhcp_layer.setClientHardwareAddress(request_dhcp_layer.getClientHardwareAddress());
    dhcp_layer.getDhcpHeader()->transactionID = request_dhcp_layer.getDhcpHeader()->transactionID;

    pcpp::Packet packet(Config::DEFAULT_PACKET_SIZE);
    packet.addLayer(&eth_layer);
    packet.addLayer(&ipv4_layer);
    packet.addLayer(&udp_layer);
    packet.addLayer(&dhcp_layer);
    packet.computeCalculateFields();

    const auto device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_1);
    device1->sendPacket(packet);
}

void DhcpServer::addNewDhcpEntry(const pcpp::MacAddress &client_mac_address, const pcpp::IPv4Address &offered_ip, const uint32_t expiry_time)
{
    _lease_map.emplace(client_mac_address.toString(),LeaseEntry(offered_ip,expiry_time));
}

bool DhcpServer::sendDhcpOffer(const pcpp::IPv4Address &offered_ip ,const pcpp::DhcpLayer& discover_dhcp_layer)
{
    pcpp::EthLayer eth_layer(Config::DPDK_DEVICE1_MAC_ADDRESS,discover_dhcp_layer.getClientHardwareAddress());

    pcpp::IPv4Layer ipv4_layer(Config::DPDK_DEVICE1_IP,Config::BROADCAST_IP);
    ipv4_layer.getIPv4Header()->timeToLive = Config::DEFAULT_TTL;

    pcpp::UdpLayer udp_layer(Config::DHCP_SERVER_PORT,Config::DHCP_CLIENT_PORT);

    pcpp::DhcpLayer dhcp_layer;
    dhcp_layer.setMessageType(pcpp::DHCP_OFFER);
    dhcp_layer.setClientHardwareAddress(discover_dhcp_layer.getClientHardwareAddress());
    dhcp_layer.setYourIpAddress(offered_ip);
    dhcp_layer.getDhcpHeader()->transactionID = discover_dhcp_layer.getDhcpHeader()->transactionID;

    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DHCP_LEASE_TIME,Config::DHCP_LEASE_TIME));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_DOMAIN_NAME_SERVERS,Config::DNS_SERVER));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_SUBNET_MASK,Config::LAN_SUBNET_MASK));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_ROUTERS,Config::DPDK_DEVICE1_IP));
    dhcp_layer.addOption(pcpp::DhcpOptionBuilder(pcpp::DHCPOPT_END,nullptr,0));

    pcpp::Packet packet(Config::DEFAULT_PACKET_SIZE);
    packet.addLayer(&eth_layer);
    packet.addLayer(&ipv4_layer);
    packet.addLayer(&udp_layer);
    packet.addLayer(&dhcp_layer);
    packet.computeCalculateFields();

    const auto device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_1);
    if (device1->sendPacket(packet))
    {
        return true;
    }
    return false;
}

DhcpServer::~DhcpServer()
{
    _is_running = false;
    if (_lease_cleanup_thread.joinable())
    {
        _lease_cleanup_thread.join();
    }
}

DhcpServer & DhcpServer::getInstance()
{
    static DhcpServer instance;
    return instance;
}

void DhcpServer::handleDhcpDiscover(const pcpp::DhcpLayer &dhcp_layer)
{
    std::lock_guard lock(_lease_mutex);
    if (!_dhcp_pool.empty())
    {
        const pcpp::IPv4Address& offered_ip = _dhcp_pool.front();
        if (sendDhcpOffer(offered_ip, dhcp_layer))
        {
            _dhcp_pool.pop_front();
            addNewDhcpEntry(dhcp_layer.getClientHardwareAddress(), offered_ip, Config::DHCP_IDLE_TIMEOUT);
        }
    }
}

void DhcpServer::handleDhcpRequest(const pcpp::DhcpLayer &dhcp_layer)
{
    const std::string& client_mac_address = dhcp_layer.getClientHardwareAddress().toString();
    const auto& requested_ip = dhcp_layer.getOptionData(pcpp::DHCPOPT_DHCP_REQUESTED_ADDRESS).getValueAsIpAddr();

    std::lock_guard lock(_lease_mutex);
    const auto& it =  _lease_map.find(client_mac_address);
    if ( it != _lease_map.end())
    {
        if (requested_ip == it->second.offered_ip_address)
        {
            if(sendDhcpAck(requested_ip, dhcp_layer))
            {
                it->second.expiry_time = Config::DHCP_LEASE_TIME;
            }
        }
        else
        {
            if (const auto& ip_iterator = findRequestedIp(requested_ip); ip_iterator != _dhcp_pool.end())
            {
                if (sendDhcpAck(requested_ip, dhcp_layer))
                {
                    removeDhcpEntry(client_mac_address, it->second.offered_ip_address);
                    _dhcp_pool.erase(ip_iterator);
                    addNewDhcpEntry(client_mac_address,requested_ip, Config::DHCP_LEASE_TIME);
                }
            }
            else {
                sendDhcpNak(dhcp_layer);
            }
        }
    }
    else {
        if (const auto& ip_iterator = findRequestedIp(requested_ip); ip_iterator != _dhcp_pool.end())
        {
            if (sendDhcpAck(requested_ip,dhcp_layer))
            {
                _dhcp_pool.erase(ip_iterator);
                addNewDhcpEntry(client_mac_address,requested_ip, Config::DHCP_LEASE_TIME);
            }
        }
        else {
            sendDhcpNak(dhcp_layer);
        }
    }
}

void DhcpServer::DhcpClientHandler(const pcpp::DhcpLayer& dhcp_layer)
{
    const pcpp::DhcpMessageType dhcp_message = dhcp_layer.getMessageType();
    if (dhcp_message == pcpp::DHCP_DISCOVER)
    {
        handleDhcpDiscover(dhcp_layer);
    }
    else if (dhcp_message == pcpp::DHCP_REQUEST)
    {
        handleDhcpRequest(dhcp_layer);
    }
    else if (dhcp_message == pcpp::DHCP_RELEASE)
    {
        handleDhcpRealse(dhcp_layer);
    }
}
