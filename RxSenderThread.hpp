#pragma once
#include <DpdkDeviceList.h>
#include <DpdkDevice.h>
#include "QueuesManager.hpp"
#include <EthLayer.h>
#include <IPv4Layer.h>
#include "Config.hpp"

class RxSenderThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _rx_device2;
    bool _stop;
    uint32_t _coreId;

public:
    RxSenderThread(pcpp::DpdkDevice* rx_device);
    ~RxSenderThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;

    bool isLocalNetworkPacket(const pcpp::IPv4Address& dest_ip, const pcpp::IPv4Address& local_ip, const pcpp::IPv4Address& subnet_mask);
};



