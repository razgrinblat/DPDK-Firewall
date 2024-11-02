#include "ArpHandler.hpp"


ArpHandler::~ArpHandler() {
}


ArpHandler & ArpHandler::getInstance()
{
    static ArpHandler instance;
    return instance;
}

void ArpHandler::handleReceivedArpRequest(const pcpp::ArpLayer& arp_layer)
{
    auto existingEntry = _cache.find(arp_layer.getSenderIpAddr().toString());
    if (existingEntry != _cache.end())
    {
        if( existingEntry->second != arp_layer.getSenderMacAddress().toString()) //if there is a different arp entry to this specific ip
        {
            std::cout << "[WARNING] Potential ARP spoofing detected: "
                      << "IP " << arp_layer.getSenderIpAddr().toString()
                      << " was previously associated with MAC "
                      << existingEntry->second << " but now has MAC "
                      << arp_layer.getSenderMacAddress().toString() << std::endl;
            return;
        }
    }
    {
        std::lock_guard<std::mutex> lock_guard(_cache_mutex);
        _cache[arp_layer.getSenderIpAddr().toString()] = arp_layer.getSenderMacAddress().toString(); //update or add the ARP cache
    }
    sendArpResponse(arp_layer.getSenderIpAddr(),arp_layer.getSenderMacAddress(),DPDK_DEVICE2_IP,DPDK_DEVICE2_MAC_ADDRESS,DPDK_DEVICE_2);
}

void ArpHandler::handleReceivedArpResponse(const pcpp::ArpLayer &arp_layer)
{
    std::string sender_ip = arp_layer.getSenderIpAddr().toString();
    if (_pending_arp_requests.find(sender_ip) != _pending_arp_requests.end()) {
        {
            std::lock_guard<std::mutex> lock(_cache_mutex);
            _cache[sender_ip] = arp_layer.getSenderMacAddress().toString(); // Update ARP cache
        }
        _arp_response_received.notify_all();
    }
    else
    {
        std::cout << "[WARNING] Potential ARP spoofing detected: "
                      << "IP " << sender_ip
                      << " was sent a response that not requested!" << std::endl;
    }
}

void ArpHandler::handleReceivedArpPacket(const pcpp::ArpLayer &arp_layer)
{
    if (arp_layer.getTargetIpAddr() == DPDK_DEVICE2_IP) {
        int opcode = arp_layer.getArpHeader()->opcode;
        if(opcode == ARP_REQUEST_OPCODE) { //request
            handleReceivedArpRequest(arp_layer);
        }
        else { //response
            handleReceivedArpResponse(arp_layer);
        }
    }
}

void ArpHandler::sendArpRequest(const pcpp::IPv4Address &target_ip)
{
    std::string target_ip_str = target_ip.toString();
    {
        // Check if an ARP request for this IP is already pending
        std::lock_guard<std::mutex> lock(_cache_mutex);
        if (_pending_arp_requests.find(target_ip_str) != _pending_arp_requests.end()) {
            return;
        }
        _pending_arp_requests.insert(target_ip_str);
    }

    // Launch a new thread to handle the ARP request
    std::thread([this, target_ip_str, target_ip]() {
        int attempts = 0;               // Current attempt count
        bool response_received = false;

        const auto device = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_2);

        // Loop to retry ARP requests
        while (attempts < MAX_RETRIES && !response_received) {
            // Create and send ARP request packet
            pcpp::EthLayer ethLayer(DPDK_DEVICE2_MAC_ADDRESS, BROADCAST_MAC_ADDRESS, PCPP_ETHERTYPE_ARP);
            pcpp::ArpLayer arpLayer(pcpp::ARP_REQUEST, DPDK_DEVICE2_MAC_ADDRESS, pcpp::MacAddress::Zero, DPDK_DEVICE2_IP, target_ip);
            pcpp::Packet arpRequestPacket(100);
            arpRequestPacket.addLayer(&ethLayer);
            arpRequestPacket.addLayer(&arpLayer);
            arpRequestPacket.computeCalculateFields();

            if (!device->sendPacket(arpRequestPacket)) {
                throw std::runtime_error("Error: Couldn't send the ARP request.");
            }

            // Wait for a response or timeout
            std::unique_lock<std::mutex> lock(_cache_mutex);
            if (_arp_response_received.wait_for(lock, std::chrono::milliseconds(SLEEP_DURATION), [&]() {
                    return _cache.find(target_ip_str) != _cache.end();
                })) {
                // ARP response received; exit the thread
                response_received = true;
                break;
            }

            attempts++;
        }

        // Remove the IP from pending requests
        {
            std::lock_guard<std::mutex> lock(_cache_mutex);
            _pending_arp_requests.erase(target_ip_str);
        }

    }).detach(); // Detach the thread to let it run independently
}


pcpp::MacAddress ArpHandler::getMacAddress(const pcpp::IPv4Address &ip)
{
    std::lock_guard<std::mutex> lock(_cache_mutex);
    auto it = _cache.find(ip.toString());
    return (it != _cache.end()) ? it->second : pcpp::MacAddress::Zero;
}

void ArpHandler::printArpCache()
{
    std::lock_guard<std::mutex> lock_guard(_cache_mutex);
    std::cout << "ARP cache:" << std::endl;
    std::cout << std::left << std::setw(20) << "IP Address" << "MAC Address" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    for (const auto& entry : _cache) {
        std::cout << std::left << std::setw(20) << entry.first
                  << entry.second << std::endl;
    }
}

void ArpHandler::sendArpResponse(const pcpp::IPv4Address &target_ip, const pcpp::MacAddress &target_mac,
                                 const pcpp::IPv4Address &requester_ip, const pcpp::MacAddress &requester_mac, uint16_t device_id)
{
    pcpp::EthLayer eth_layer(requester_mac,target_mac,PCPP_ETHERTYPE_ARP);
    pcpp::ArpLayer arp_layer(pcpp::ARP_REPLY,requester_mac,target_mac,requester_ip,target_ip);
    pcpp::Packet arp_response_packet(100);
    arp_response_packet.addLayer(&eth_layer);
    arp_response_packet.addLayer(&arp_layer);
    arp_response_packet.computeCalculateFields();
    auto device =  pcpp::DpdkDeviceList::getInstance().getDeviceByPort(device_id);
    if (!device->sendPacket(arp_response_packet))
    {
        throw std::runtime_error ("Error: Couldn't send the ARP response.");
    }
}
