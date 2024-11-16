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

public:
    TxReceiverThread(pcpp::DpdkDevice* tx_device);
    ~TxReceiverThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



