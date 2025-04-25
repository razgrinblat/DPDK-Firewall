#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include "RuleTree.hpp"
#include "ArpHandler.hpp"
#include "ClientsManager.hpp"
#include "IcmpHandler.hpp"
#include "PacketStats.hpp"
#include "FirewallLogger.hpp"

class RxReceiverThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _rx_device1;
    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> _rx_queue;
    bool _stop;
    uint32_t _coreId;
    QueuesManager& _queues_manager;
    RuleTree& _rule_tree;
    ArpHandler& _arp_handler;
    IcmpHandler& _icmp_handler;
    PacketStats& _packet_stats;
    ClientsManager& _clients_manager;

    void pushPacketToQueue(std::vector<pcpp::MBufRawPacket*>& packets_to_queue) const;

public:
    RxReceiverThread(pcpp::DpdkDevice* rx_device);
    ~RxReceiverThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



