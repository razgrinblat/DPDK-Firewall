#include "ArpHandler.hpp"


ArpHandler::ArpHandler()
{

}

ArpHandler::~ArpHandler() {
}

void ArpHandler::handleArpRequestFromClient(const pcpp::ArpLayer &arp_layer)
{
    std::string requested_ip = arp_layer.getTargetIpAddr().toString();
    if(_cache.find(requested_ip) != _cache.end()) {
        pcpp::MacAddress requested_mac = _cache[requested_ip];
        sendArpResponse(CLIENT_IP,CLIENT_MAC_ADDRESS,requested_ip,requested_mac,DPDK_DEVICE_1);
    }
    else {
        //send the arp request and save it in last_requests vector
    }

}

void ArpHandler::handleArpResponseToClient() {
}

void ArpHandler::handleArpRequest(const pcpp::ArpLayer& arp_layer)
{
    if(arp_layer.getTargetIpAddr() == DPDK_DEVICE2_IP)
    {
        auto existingEntry = _cache.find(arp_layer.getSenderIpAddr().toString());
        if (existingEntry != _cache.end())
        {
            if( existingEntry->second != arp_layer.getSenderMacAddress().toString())
            {
                std::cout << "[WARNING] Potential ARP spoofing detected: "
                          << "IP " << arp_layer.getSenderIpAddr().toString()
                          << " was previously associated with MAC "
                          << existingEntry->second << " but now has MAC "
                          << arp_layer.getSenderMacAddress().toString() << std::endl;
                return;
            }
        }
        _cache[arp_layer.getSenderIpAddr().toString()] = arp_layer.getSenderMacAddress().toString(); //update or add the ARP cache
        sendArpResponse(arp_layer.getSenderIpAddr(),arp_layer.getSenderMacAddress(),DPDK_DEVICE2_IP,DPDK_DEVICE2_MAC_ADDRESS,DPDK_DEVICE_2);
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

bool ArpHandler::lookUp()
{

}

void ArpHandler::updateCache()
{

}
