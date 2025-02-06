#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include "ArpHandler.hpp"
#include "IcmpHandler.hpp"
#include "PacketStats.hpp"
#include "TcpSessionHandler.hpp"
#include "RuleTree.hpp"

class TxReceiverThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _tx_device1;
    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> _tx_queue;
    bool _stop;
    uint32_t _coreId;
    QueuesManager& _queues_manager;
    RuleTree& _rule_tree;
    ArpHandler& _arp_handler;
    IcmpHandler& _icmp_handler;
    PacketStats& _packet_stats;

    void pushPacketToQueue(std::vector<pcpp::MBufRawPacket*>& packets_to_queue) const;

public:
    TxReceiverThread(pcpp::DpdkDevice* tx_device);
    ~TxReceiverThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



