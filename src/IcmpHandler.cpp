#include "IcmpHandler.hpp"

IcmpHandler::IcmpHandler() : _client_manager(ClientsManager::getInstance()), _packet_stats(PacketStats::getInstance())
{}

void IcmpHandler::sendIcmpResponse(const pcpp::MacAddress &dst_mac, const pcpp::IPv4Address &dst_ip, pcpp::IcmpLayer& icmp_request_layer, const uint16_t sender_device_id) const
{
    const auto& src_mac = (sender_device_id == Config::DPDK_DEVICE_1) ? Config::DPDK_DEVICE1_MAC_ADDRESS : Config::DPDK_DEVICE2_MAC_ADDRESS;
    const auto& src_ip = (sender_device_id == Config::DPDK_DEVICE_1) ? Config::DPDK_DEVICE1_IP : Config::DPDK_DEVICE2_IP;

    pcpp::EthLayer eth_layer(src_mac,dst_mac,PCPP_ETHERTYPE_IP);

    pcpp::IPv4Layer ip_layer(src_ip,dst_ip);
    ip_layer.getIPv4Header()->protocol = pcpp::IPProtocolTypes::PACKETPP_IPPROTO_ICMP;
    ip_layer.getIPv4Header()->timeToLive = Config::DEFAULT_TTL;

    const auto request_header = icmp_request_layer.getEchoRequestData()->header;
    pcpp::IcmpLayer icmp_layer;
    icmp_layer.setEchoReplyData(pcpp::hostToNet16(request_header->id), pcpp::hostToNet16(request_header->sequence), 0,
    icmp_request_layer.getLayerPayload(), icmp_request_layer.getLayerPayloadSize());

    pcpp::Packet icmp_response(Config::DEFAULT_PACKET_SIZE);
    icmp_response.addLayer(&eth_layer);
    icmp_response.addLayer(&ip_layer);
    icmp_response.addLayer(&icmp_layer);
    icmp_response.computeCalculateFields();

    sendPacketHandler(icmp_response, sender_device_id);
}

void IcmpHandler::sendPacketHandler(pcpp::Packet &packet, const uint16_t sender_device_id) const
{
    const auto device =  pcpp::DpdkDeviceList::getInstance().getDeviceByPort(sender_device_id);
    if (!device->sendPacket(packet))
    {
        std::cerr << "Error: Couldn't send the ICMP response.";
    }
    else {
        _packet_stats.consumePacket(packet);
    }
}

IcmpHandler & IcmpHandler::getInstance()
{
    static IcmpHandler instance;
    return instance;
}

bool IcmpHandler::processInBoundIcmp(pcpp::Packet& parsed_packet)
{
    pcpp::IcmpLayer* icmp_layer = parsed_packet.getLayerOfType<pcpp::IcmpLayer>();
    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();

    if (icmp_layer->getMessageType() == pcpp::ICMP_ECHO_REQUEST)
    {
        sendIcmpResponse(eth_layer->getSourceMac(), ipv4_layer->getSrcIPv4Address(),*icmp_layer, Config::DPDK_DEVICE_2);
        return false;
    }
    if (icmp_layer->getMessageType() == pcpp::ICMP_ECHO_REPLY)
    {
        const uint16_t received_icmp_id  = icmp_layer->getEchoReplyData()->header->id;

        std::lock_guard lock(_icmp_table_mutex);
        auto it = _icmp_request_table.find(received_icmp_id);
        if (it != _icmp_request_table.end())
        {
            const pcpp::IPv4Address& client_ip = _icmp_request_table[received_icmp_id];
            ipv4_layer->setDstIPv4Address(client_ip);
            eth_layer->setSourceMac(Config::DPDK_DEVICE1_MAC_ADDRESS);
            eth_layer->setDestMac(_client_manager.getClientMacAddress(client_ip));

            _icmp_request_table.erase(it);
        }
    }
    return true;
}

bool IcmpHandler::processOutBoundIcmp(pcpp::Packet& parsed_packet)
{
    pcpp::IcmpLayer* icmp_layer = parsed_packet.getLayerOfType<pcpp::IcmpLayer>();

    if (icmp_layer->getMessageType() == pcpp::ICMP_ECHO_REQUEST)
    {
        const pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
        const pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
        const pcpp::IPv4Address src_client_ip = ipv4_layer->getSrcIPv4Address();

        if (ipv4_layer->getDstIPv4Address() == Config::DPDK_DEVICE1_IP)
        {
            sendIcmpResponse(eth_layer->getSourceMac(), src_client_ip,*icmp_layer, Config::DPDK_DEVICE_1);
            return false;
        }

        const uint16_t icmp_id = icmp_layer->getEchoRequestData()->header->id;

        std::lock_guard lock(_icmp_table_mutex);
        _icmp_request_table[icmp_id] = src_client_ip;
    }
    return true;
}