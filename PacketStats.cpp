#include "PacketStats.hpp"

PacketStats::PacketStats() : _ethPacketCount(0), _ipv4PacketCount(0), _ipv6PacketCount(0),
                             _tcpPacketCount(0), _udpPacketCount(0), _dnsPacketCount(0), _httpPacketCount(0),
                             _sslPacketCount(0), _arpPacketCount(0), _icmpPacketCount(0), _sshPacketCount(0),
                             _ftpPacketCount(0), _ws_client(WebSocketClient::getInstance()) {}

PacketStats & PacketStats::getInstance()
{
    static PacketStats stats;
    return stats;
}

void PacketStats::consumePacket(const pcpp::Packet &packet)
{
    if (packet.isPacketOfType(pcpp::Ethernet))
        _ethPacketCount++;
    if (packet.isPacketOfType(pcpp::IPv4))
        _ipv4PacketCount++;
    if (packet.isPacketOfType(pcpp::IPv6))
        _ipv6PacketCount++;
    if (packet.isPacketOfType(pcpp::TCP))
        _tcpPacketCount++;
    if (packet.isPacketOfType(pcpp::UDP))
        _udpPacketCount++;
    if (packet.isPacketOfType(pcpp::DNS))
        _dnsPacketCount++;
    if (packet.isPacketOfType(pcpp::HTTP))
        _httpPacketCount++;
    if (packet.isPacketOfType(pcpp::SSL))
        _sslPacketCount++;
    if (packet.isPacketOfType(pcpp::ARP))
        _arpPacketCount++;
    if(packet.isPacketOfType(pcpp::ICMP))
        _icmpPacketCount++;
    if(packet.isPacketOfType(pcpp::SSH))
        _sshPacketCount++;
    if(packet.isPacketOfType(pcpp::FTP))
        _ftpPacketCount++;
}


void PacketStats::printToConsole() const
{
    std::cout
            << "Ethernet packet count: " << _ethPacketCount << std::endl
            << "IPv4 packet count:     " << _ipv4PacketCount << std::endl
            << "IPv6 packet count:     " << _ipv6PacketCount << std::endl
            << "TCP packet count:      " << _tcpPacketCount << std::endl
            << "UDP packet count:      " << _udpPacketCount << std::endl
            << "DNS packet count:      " << _dnsPacketCount << std::endl
            << "HTTP packet count:     " << _httpPacketCount << std::endl
            << "SSL packet count:      " << _sslPacketCount << std::endl
            << "ARP packet count:      " << _arpPacketCount << std::endl
            << "ICMP packet count:     " << _icmpPacketCount << std::endl
            << "SSH packet count:      " << _sshPacketCount << std::endl
            << "FTP packet count:      " << _ftpPacketCount << std::endl;
}

void PacketStats::sendPacketStats()
{
    Json::Value packetStats;
    packetStats["type"] = "packet stats"; // Title field
    packetStats["ethPacketCount"] = ++_ethPacketCount;
    packetStats["ipv4PacketCount"] = ++_ipv4PacketCount;
    packetStats["ipv6PacketCount"] = _ipv6PacketCount;
    packetStats["tcpPacketCount"] = _tcpPacketCount;
    packetStats["udpPacketCount"] = _udpPacketCount;
    packetStats["dnsPacketCount"] = _dnsPacketCount;
    packetStats["httpPacketCount"] = ++_httpPacketCount;
    packetStats["sslPacketCount"] = _sslPacketCount;
    packetStats["arpPacketCount"] = _arpPacketCount;
    packetStats["icmpPacketCount"] = _icmpPacketCount;
    packetStats["sshPacketCount"] = _sshPacketCount;
    packetStats["ftpPacketCount"] = _ftpPacketCount;

    // Convert JSON object to string
    const Json::StreamWriterBuilder writer;
    const std::string message = writeString(writer, packetStats);

    // Send message via WebSocket
    _ws_client.send(message);
}