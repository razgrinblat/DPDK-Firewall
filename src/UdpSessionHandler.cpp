#include "UdpSessionHandler.hpp"

UdpSessionHandler::UdpSessionHandler(): _session_table(SessionTable::getInstance()), _port_allocator(PortAllocator::getInstance())
{}

std::unique_ptr<SessionTable::Session> UdpSessionHandler::initUdpSession(const pcpp::Packet &tcp_packet) const
{
    const pcpp::IPv4Layer* ipv4_layer = tcp_packet.getLayerOfType<pcpp::IPv4Layer>();
    const pcpp::UdpLayer* udp_layer = tcp_packet.getLayerOfType<pcpp::UdpLayer>();
    return std::make_unique<SessionTable::Session>(
        SessionTable::UDP_PROTOCOL,
       ipv4_layer->getSrcIPv4Address(),
       ipv4_layer->getDstIPv4Address(),
       udp_layer->getSrcPort(),
       udp_layer->getDstPort(),
       SessionTable::UDP
   );
}

UdpSessionHandler & UdpSessionHandler::getInstance()
{
    static UdpSessionHandler instance;
    return instance;
}

void UdpSessionHandler::processClientUdpPacket(pcpp::Packet &udp_packet)
{
    const uint32_t udp_hash = hash5Tuple(&udp_packet);
    const uint32_t packet_size = udp_packet.getRawPacket()->getRawDataLen();

    if (_session_table.isSessionExists(udp_hash))
    {
        _session_table.updateSession(udp_hash,SessionTable::UDP,packet_size,true);
    }
    else
    {
        _session_table.addNewSession(udp_hash, std::move(initUdpSession(udp_packet)),SessionTable::UDP,packet_size);
    }
    // change port to firewall port
    const auto udp_layer = udp_packet.getLayerOfType<pcpp::UdpLayer>();
    udp_layer->getUdpHeader()->portSrc = pcpp::hostToNet16(_session_table.getFirewallPort(udp_hash));
}

bool UdpSessionHandler::isValidInternetUdpPacket(pcpp::Packet &udp_packet)
{
    const uint32_t udp_hash = hash5Tuple(&udp_packet);

    if (_session_table.isSessionExists(udp_hash))
    {
        _session_table.updateSession(udp_hash, SessionTable::UDP,udp_packet.getRawPacket()->getRawDataLen(),false);
        return true;
    }
    const auto ip_layer = udp_packet.getLayerOfType<pcpp::IPv4Layer>();
    std::cerr << "Blocked Unexpected UDP packet from IP: " << ip_layer->getSrcIPv4Address() << std::endl;
    return false;
}
