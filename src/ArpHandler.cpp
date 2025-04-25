#include "ArpHandler.hpp"

ArpHandler::ArpHandler():_stop_flag(false), _packet_stats(PacketStats::getInstance())
{}

ArpHandler::~ArpHandler()
{
    stopThreads();
}

ArpHandler & ArpHandler::getInstance()
{
    static ArpHandler instance;
    return instance;
}

void ArpHandler::stopThreads()
{
    _stop_flag.store(true);

    for (auto& thread : _threads)
    {
        if(thread.joinable())
        {
            thread.join();
        }
    }
}

void ArpHandler::handleReceivedArpRequest(const pcpp::ArpLayer& arp_layer)
{
    const auto existingEntry = _cache.find(arp_layer.getSenderIpAddr().toString());
    if (existingEntry != _cache.end() && existingEntry->second != arp_layer.getSenderMacAddress().toString())
    {
         //if there is a different arp entry to this specific ip
        throw BlockedPacket("Potential ARP spoofing detected: "
                  "IP " + arp_layer.getSenderIpAddr().toString()
                  + " was previously associated with MAC "
                  + existingEntry->second + " but now has MAC "
                  + arp_layer.getSenderMacAddress().toString());
    }
    {
        std::lock_guard lock(_cache_mutex);
        _cache[arp_layer.getSenderIpAddr().toString()] = arp_layer.getSenderMacAddress().toString(); //update or add the ARP cache
    }
    sendArpResponsePacket(arp_layer.getSenderIpAddr(),arp_layer.getSenderMacAddress(), Config::DPDK_DEVICE_2);
}

void ArpHandler::handleReceivedArpResponse(const pcpp::ArpLayer &arp_layer)
{
    const std::string sender_ip = arp_layer.getSenderIpAddr().toString();
    if (_unresolved_arp_requests.find(sender_ip) != _unresolved_arp_requests.end())
    {
        {
            std::lock_guard lock(_cache_mutex);
            _cache[sender_ip] = arp_layer.getSenderMacAddress().toString(); // Update ARP cache
        }
        _arp_response_received.notify_all();
    }
    else
    {
       throw BlockedPacket("[WARNING] Potential ARP spoofing detected: "
                      "IP " + sender_ip
                      + " was sent a response that not requested!");
    }
}

void ArpHandler::handleReceivedArpPacket(const pcpp::ArpLayer& arp_layer)
{
    if (arp_layer.getTargetIpAddr() == Config::DPDK_DEVICE2_IP)
    {
        const uint16_t opcode = arp_layer.getArpHeader()->opcode;
        try
        {
            if(opcode == Config::ARP_REQUEST_OPCODE) { //Arp request
                handleReceivedArpRequest(arp_layer);
            }
            else { //Arp response
                handleReceivedArpResponse(arp_layer);
            }
        }catch (const std::exception& e)
        {
            std::cerr << e.what() << std::endl;
        }
    }
}

void ArpHandler::sendArpRequest(const pcpp::IPv4Address& target_ip)
{
    if (isRequestAlreadyPending(target_ip) || _stop_flag.load())
    {
        return; //request is already pending
    }

    // Launch a new thread to handle the ARP request
    _threads.emplace_back([this,target_ip]()
    {
        threadHandler(target_ip);
    });
}

pcpp::MacAddress ArpHandler::getMacAddress(const pcpp::IPv4Address& ip)
{
    std::lock_guard lock(_cache_mutex);
    const auto it = _cache.find(ip.toString());
    return (it != _cache.end()) ? it->second : pcpp::MacAddress::Zero;
}

void ArpHandler::printArpCache()
{
    std::lock_guard lock_guard(_cache_mutex);
    std::cout << "ARP cache:" << std::endl;
    std::cout << std::left << std::setw(20) << "IP Address" << "MAC Address" << std::endl;
    std::cout << "------------------------------" << std::endl;

    for (const auto& entry : _cache)
    {
        std::cout << std::left << std::setw(20) << entry.first << entry.second << std::endl;
    }
}

void ArpHandler::sendArpResponsePacket(const pcpp::IPv4Address& target_ip, const pcpp::MacAddress& target_mac, const uint16_t sender_device_id) const
{

    const auto& source_mac = (sender_device_id == Config::DPDK_DEVICE_1) ? Config::DPDK_DEVICE1_MAC_ADDRESS : Config::DPDK_DEVICE2_MAC_ADDRESS;
    const auto& source_ip = (sender_device_id == Config::DPDK_DEVICE_1) ? Config::DPDK_DEVICE1_IP : Config::DPDK_DEVICE2_IP;

    pcpp::EthLayer eth_layer(source_mac,target_mac,PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arp_layer(pcpp::ARP_REPLY,source_mac,target_mac,source_ip,target_ip);
    pcpp::Packet arp_response_packet(Config::DEFAULT_PACKET_SIZE);
    arp_response_packet.addLayer(&eth_layer);
    arp_response_packet.addLayer(&arp_layer);
    arp_response_packet.computeCalculateFields();
    const auto device =  pcpp::DpdkDeviceList::getInstance().getDeviceByPort(sender_device_id);
    if (!device->sendPacket(arp_response_packet))
    {
        FirewallLogger::getInstance().error("Couldn't send the ARP response.");
    }
    else {
        _packet_stats.consumePacket(arp_response_packet);
    }
}

bool ArpHandler::isRequestAlreadyPending(const pcpp::IPv4Address& target_ip)
{
    std::string target_ip_str = target_ip.toString();
    {
        // Check if an ARP request for this IP is already pending
        std::lock_guard lock(_cache_mutex);
        if (_unresolved_arp_requests.find(target_ip_str) != _unresolved_arp_requests.end())
        {
            return true;
        }
        _unresolved_arp_requests.insert(target_ip_str); // Request was not pending and is now added
    }
    return false;
}

void ArpHandler::threadHandler(const pcpp::IPv4Address& target_ip)
{
    int attempts = 0;               // Current attempt count
    const std::string target_ip_str = target_ip.toString();

    // Loop to retry ARP requests
    while (attempts < Config::MAX_RETRIES && !_stop_flag.load())
    {
        // Create and send ARP request packet
        if (!sendArpRequestPacket(target_ip))
        {
            FirewallLogger::getInstance().error("Couldn't send the ARP request.");
        }
        // Wait for a response or timeout
        std::unique_lock lock(_cache_mutex);
        if (_arp_response_received.wait_for(lock, std::chrono::milliseconds(Config::SLEEP_DURATION), [&]()
            {
                return _cache.find(target_ip_str) != _cache.end();
            })) {
            // ARP response received; exit the thread
            break;
            }
        attempts++;
    }
    removePendingRequest(target_ip); //remove the ARP from the pending_arp_list if resolved
}

bool ArpHandler::sendArpRequestPacket(const pcpp::IPv4Address& target_ip)
{
    // Create and send ARP request packet
    pcpp::EthLayer ethLayer(Config::DPDK_DEVICE2_MAC_ADDRESS, Config::BROADCAST_MAC_ADDRESS, PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, Config::DPDK_DEVICE2_MAC_ADDRESS,
        pcpp::MacAddress::Zero, Config::DPDK_DEVICE2_IP, target_ip);
    pcpp::Packet arp_request_packet(Config::DEFAULT_PACKET_SIZE);
    arp_request_packet.addLayer(&ethLayer);
    arp_request_packet.addLayer(&arpLayer);
    arp_request_packet.computeCalculateFields();

    const auto device = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_2);
    if (device->sendPacket(arp_request_packet))
    {
        _packet_stats.consumePacket(arp_request_packet);
        return true;
    }
    return false;
}

void ArpHandler::removePendingRequest(const pcpp::IPv4Address& target_ip)
{
    std::lock_guard lock(_cache_mutex);
    _unresolved_arp_requests.erase(target_ip.toString());
}