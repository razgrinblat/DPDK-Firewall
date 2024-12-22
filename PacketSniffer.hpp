#pragma once
#include "DpdkDevice.h"
#include  "DpdkDeviceList.h"
#include "PacketStats.hpp"
#include "IPv4Layer.h"
#include "EthLayer.h"
#include "ArpLayer.h"
#include "SystemUtils.h"
#include "IcmpLayer.h"
#include "PcapLiveDeviceList.h"
#include "RxReceiverThread.hpp"
#include "RxSenderThread.hpp"
#include "TxReceiverThread.hpp"
#include "TxSenderThread.hpp"

class PacketSniffer
{
private:
    pcpp::DpdkDevice* _device1;
    pcpp::DpdkDevice* _device2;
    std::vector<pcpp::DpdkWorkerThread*> _workers_threads;
    bool _keep_running;
    RuleTree& _rule_tree;

    void openDpdkDevices();
    void printDeviceInfo() const;
    static void onApplicationInterruptedCallBack(void* cookie);
    void startingDpdkThreads();
    void closeDevices();

public:
    PacketSniffer();
    ~PacketSniffer();

    void startingCapture();

};




