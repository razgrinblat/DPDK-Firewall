#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "Config.hpp"
#include "PacketStats.hpp"
#include "ArpHandler.hpp"
#include "TcpSessionHandler.hpp"

class RxSenderThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _rx_device2;
    bool _stop;
    uint32_t _coreId;
    QueuesManager& _queues_manager;
    ArpHandler& _arp_handler;
    PacketStats& _packet_stats;
    TcpSessionHandler& _session_handler;

    bool isLocalNetworkPacket(const pcpp::IPv4Address& dest_ip, const pcpp::IPv4Address& local_ip, const pcpp::IPv4Address& subnet_mask);
    void fetchPacketToProcess(std::vector<pcpp::MBufRawPacket*>& packets_to_process) const;
    void updateEthernetAndIpLayers(pcpp::Packet& parsed_packet, const pcpp::MacAddress& dest_mac);
    bool handleLocalNetworkPacket(const pcpp::IPv4Address &dest_ip, pcpp::Packet &parsed_packet);

public:
    RxSenderThread(pcpp::DpdkDevice* rx_device);
    ~RxSenderThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



