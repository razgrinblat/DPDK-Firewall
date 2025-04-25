#pragma once
#include <IcmpLayer.h>
#include <mutex>
#include <Packet.h>
#include "ClientsManager.hpp"
#include "PacketStats.hpp"
#include "FirewallLogger.hpp"
#include <DpdkDeviceList.h>

class IcmpHandler
{
private:

    std::unordered_map<uint16_t,pcpp::IPv4Address> _icmp_request_table; //ICMP ID to client IP
    std::mutex _icmp_table_mutex;
    ClientsManager& _client_manager;
    PacketStats& _packet_stats;

    IcmpHandler();
    void sendIcmpResponse(const pcpp::MacAddress& dst_mac, const pcpp::IPv4Address& dst_ip, pcpp::IcmpLayer& icmp_request_layer,
        uint16_t sender_device_id) const;
    void sendPacketHandler(pcpp::Packet& packet, uint16_t sender_device_id) const;

public:
    ~IcmpHandler() = default;
    IcmpHandler(const IcmpHandler&) = delete;
    IcmpHandler& operator=(const IcmpHandler&) = delete;
    static IcmpHandler& getInstance();

    void modifyInBoundIcmpResponse(pcpp::Packet& parsed_packet);

    //process internet icmp packets
    bool processInBoundIcmp(const pcpp::Packet& parsed_packet);

    //process client icmp packets
    bool processOutBoundIcmp(const pcpp::Packet& parsed_packet);

};