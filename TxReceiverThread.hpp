#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include "Config.hpp"
#include <EthLayer.h>
#include "ArpHandler.hpp"
#include "PacketStats.hpp"
#include "TcpSessionHandler.hpp"

class TxReceiverThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _tx_device1;
    bool _stop;
    uint32_t _coreId;
    std::vector<pcpp::MBufRawPacket*> _packets_to_client;
    QueuesManager& _queues_manager;
    ArpHandler& _arp_handler;
    PacketStats& _packet_stats;
    TcpSessionHandler& _session_handler;

    void pushToTxQueue();
    void processReceivedPackets(std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST>& mbuf_array);
    void processSinglePacket(pcpp::MBufRawPacket* raw_packet);

public:
    TxReceiverThread(pcpp::DpdkDevice* tx_device);
    ~TxReceiverThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



