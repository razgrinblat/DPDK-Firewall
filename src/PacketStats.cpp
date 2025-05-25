#include "PacketStats.hpp"

#include "Config.hpp"

PacketStats::PacketStats() : _ethPacketCount(0), _ipv4PacketCount(0),
                             _tcpPacketCount(0), _udpPacketCount(0), _dnsPacketCount(0), _httpPacketCount(0),
                             _sslPacketCount(0), _arpPacketCount(0), _icmpPacketCount(0), _sshPacketCount(0),
                             _ftpPacketCount(0), _ws_client(WebSocketClient::getInstance())
{}

void PacketStats::printDeviceStats(const pcpp::DpdkDevice::DpdkDeviceStats &device_stats)
{
    std::cout << "device ID: " << static_cast<int>(device_stats.devId) << "\n";
    std::cout << "Total Bytes Received: " << device_stats.aggregatedRxStats.bytesPerSec << "\n";
    std::cout << "Rx Throughput: " << device_stats.aggregatedRxStats.bytesPerSec << " [Bytes/sec]\n";
    std::cout << "Total Bytes Sent: " << device_stats.aggregatedTxStats.bytes << "\n";
    std::cout << "Tx Throughput: " << device_stats.aggregatedTxStats.bytesPerSec << " [Bytes/sec]\n";
}

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
    if (packet.isPacketOfType(pcpp::ICMP))
        _icmpPacketCount++;
    if (packet.isPacketOfType(pcpp::SSH))
        _sshPacketCount++;
    if (packet.isPacketOfType(pcpp::FTP))
        _ftpPacketCount++;
}

void PacketStats::printToConsole()
{
    std::cout
            << "Ethernet packet count: " << _ethPacketCount << "\n"
            << "IPv4 packet count:     " << _ipv4PacketCount << "\n"
            << "TCP packet count:      " << _tcpPacketCount << "\n"
            << "UDP packet count:      " << _udpPacketCount << "\n"
            << "DNS packet count:      " << _dnsPacketCount << "\n"
            << "HTTP packet count:     " << _httpPacketCount << "\n"
            << "SSL packet count:      " << _sslPacketCount << "\n"
            << "ARP packet count:      " << _arpPacketCount << "\n"
            << "ICMP packet count:     " << _icmpPacketCount << "\n"
            << "SSH packet count:      " << _sshPacketCount << "\n"
            << "FTP packet count:      " << _ftpPacketCount << "\n";

    pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_1)->getStatistics(_device1_stats);
    printDeviceStats(_device1_stats);

    pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_2)->getStatistics(_device2_stats);
    printDeviceStats(_device2_stats);
}

void PacketStats::sendPacketStatsToBackend()
{
    Json::Value packet_stats;
    packet_stats["type"] = "packet stats"; // Title field
    packet_stats["tcp"] = _tcpPacketCount;
    packet_stats["udp"] = _udpPacketCount;
    packet_stats["dns"] = _dnsPacketCount;
    packet_stats["http"] = _httpPacketCount;
    packet_stats["ssl"] = _sslPacketCount;
    packet_stats["arp"] = _arpPacketCount;
    packet_stats["icmp"] = _icmpPacketCount;
    packet_stats["ssh"] = _sshPacketCount;
    packet_stats["ftp"] = _ftpPacketCount;

    // Convert JSON object to string
    const Json::StreamWriterBuilder writer;
    const std::string message = writeString(writer, packet_stats);

    // Send message via WebSocket
    _ws_client.send(message);
}