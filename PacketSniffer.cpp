#include "PacketSniffer.hpp"

bool PacketSniffer::_keep_running;

void PacketSniffer::openDpdkDevices()
{
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterruptedCallBack, nullptr);

    pcpp::CoreMask core_mask_to_use = pcpp::getCoreMaskForAllMachineCores();
    pcpp::DpdkDeviceList::initDpdk(core_mask_to_use,MBUF_POOL_SIZE);

    _device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_1);
    _device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_2);

    if(_device1 == nullptr)
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(DPDK_DEVICE_1) + "'\n");
    }
    if(_device2 == nullptr)
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(DPDK_DEVICE_2) + "'\n");
    }
    if(!_device1->open() || !_device2->open())
    {
        throw std::runtime_error("Cannot open a device\n");
    }
}

void PacketSniffer::printDeviceInfo() const {
    auto device = _device1;
    for(int i=0; i<=1; i++)
    {
        std::cout
    << "Interface info: " << std::endl
    << "   Interface name: " << device->getDeviceName() << std::endl
    << "   Interface ID: " << device->getDeviceId() << std::endl
    << "   MAC address: " << device->getMacAddress() << std::endl
    << "   Default PMD name (Driver Name): " << device->getPMDName() << std::endl;
        device = _device2;
    }
}

void PacketSniffer::onApplicationInterruptedCallBack(void* cookie)
{
    _keep_running = false;
    std::cout << std::endl << "Shutting down..." << std::endl;
    pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
}

void PacketSniffer::startAsyncCapture()
{
    std::vector<pcpp::DpdkWorkerThread*> workers_threads;
    workers_threads.emplace_back(new RxReceiverThread(_device1));
    workers_threads.emplace_back(new RxSenderThread(_device2));
    workers_threads.emplace_back(new TxReceiverThread(_device2));
    workers_threads.emplace_back(new TxSenderThread(_device1));

    int workersCoreMask = 0;
    for (int i = 1; i <= CORES_TO_USE; i++)
    {
        workersCoreMask = workersCoreMask | (1 << i);
    }

    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, workers_threads))
    {
        throw std::runtime_error("Couldn't start worker threads\n");
    }
    std::cout << "starting capture\n";

    PacketStats& packet_stats = PacketStats::getInstance();
    ArpHandler& arp_handler = ArpHandler::getInstance();
    std::string user_input;
    while (_keep_running) {
        std::cout << "------------------------------\n";
        std::cout << "Enter 'arp' to view ARP cache or 'p' to view packet stats:\n";
        std::cout << "------------------------------\n";

        std::getline(std::cin, user_input);

        if (user_input == "arp") {
            arp_handler.printArpCache();
        }
        else if (user_input == "p") {
            std::cout << "Displaying Packet Statistics:\n";
            packet_stats.printToConsole();
        }
        else {
            std::cout << "Invalid input. Please try again.\n";
        }
    }
}

PacketSniffer::PacketSniffer()
{
    _keep_running = true;
    openDpdkDevices();
    printDeviceInfo();
    startAsyncCapture();

}

PacketSniffer::~PacketSniffer()
{
    if (_device1 != nullptr && _device1->isOpened())
    {
        _device1->stopCapture();
        _device1->close();
    }
    if (_device2 != nullptr && _device2->isOpened())
    {
        _device2->stopCapture();
        _device2->close();
    }
}
