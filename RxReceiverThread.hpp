#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include "PacketStats.hpp"
#include "Config.hpp"

class RxReceiverThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _rx_device1;
    bool _stop;
    uint32_t _coreId;

public:
    RxReceiverThread(pcpp::DpdkDevice* rx_device);
    ~RxReceiverThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



