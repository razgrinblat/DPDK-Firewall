#pragma once
#include <DpdkDeviceList.h>
#include "QueuesManager.hpp"
#include "Config.hpp"
#include "ArpHandler.hpp"
#include "TcpSessionHandler.hpp"
#include "UdpSessionHandler.hpp"

class RxSenderThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _rx_device2;
    bool _stop;
    uint32_t _coreId;
    QueuesManager& _queues_manager;
    ArpHandler& _arp_handler;
    TcpSessionHandler& _tcp_session_handler;
    UdpSessionHandler& _udp_session_handler;
    std::vector<pcpp::MBufRawPacket*> _packets_to_process;

    inline bool isLocalNetworkPacket(const pcpp::IPv4Address &dest_ip, const pcpp::IPv4Address &local_ip,
    const pcpp::IPv4Address &subnet_mask)
    {
        const uint32_t dest_network = dest_ip.toInt() & subnet_mask.toInt();
        const uint32_t local_network = local_ip.toInt() & subnet_mask.toInt();

        return local_network == dest_network;
    }

    void fetchPacketFromRx();
    void modifyPacketHeaders(pcpp::Packet& parsed_packet, const pcpp::MacAddress& dest_mac);
    bool resolveLocalNetworkPacket(const pcpp::IPv4Address &dest_ip);
    void sendPackets(std::array<pcpp::MBufRawPacket*, Config::MAX_RECEIVE_BURST> &packet_buffer, uint32_t packets_number);

public:
    RxSenderThread(pcpp::DpdkDevice* rx_device);
    ~RxSenderThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};