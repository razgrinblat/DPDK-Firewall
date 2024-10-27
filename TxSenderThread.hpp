#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "Config.hpp"
class TxSenderThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _tx_device2;
    bool _stop;
    uint32_t _coreId;

public:
    TxSenderThread(pcpp::DpdkDevice* tx_device);
    ~TxSenderThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



