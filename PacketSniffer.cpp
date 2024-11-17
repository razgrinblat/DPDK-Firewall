#include "PacketSniffer.hpp"

bool PacketSniffer::_keep_running;

void PacketSniffer::openDpdkDevices()
{
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterruptedCallBack, this);

    const pcpp::CoreMask core_mask_to_use = pcpp::getCoreMaskForAllMachineCores();
    pcpp::DpdkDeviceList::initDpdk(core_mask_to_use,MBUF_POOL_SIZE);

    _device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_1);
    _device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(DPDK_DEVICE_2);

    if(_device1 == nullptr || !_device1->open())
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(DPDK_DEVICE_1) + "'\n");
    }
    if(_device2 == nullptr || !_device2->open())
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(DPDK_DEVICE_2) + "'\n");
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
    auto* sniffer = static_cast<PacketSniffer*>(cookie);

    _keep_running = false;
    std::cout << std::endl << "Shutting down..." << std::endl;
    ArpHandler::getInstance().stopThreads();
    pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
    sniffer->closeDevices();
}

void PacketSniffer::startingCapture()
{
    std::cout << "starting capturing packets...\n";

    const PacketStats& packet_stats = PacketStats::getInstance();
    ArpHandler& arp_handler = ArpHandler::getInstance();
    SessionTable& session_table = SessionTable::getInstance();
    std::string user_input;
    while (_keep_running) {
        std::cout << "------------------------------\n";
        std::cout << "Enter 'arp' to view ARP cache,'p' to view packet stats, 'tcp' to view TCP session cache or 'exit' to stop:\n";
        std::cout << "------------------------------\n";

        std::getline(std::cin, user_input);

        if (user_input == "arp") {
            arp_handler.printArpCache();
        }
        else if (user_input == "p") {
            std::cout << "Displaying Packet Statistics:\n";
            packet_stats.printToConsole();
        }
        else if (user_input == "tcp") {
            session_table.printSessionCache();
        }
        else if(user_input == "exit") {
            _keep_running = false;
            ArpHandler::getInstance().stopThreads();
            pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
        }
        else {
            std::cout << "Invalid input. Please try again.\n";
        }
    }
}

void PacketSniffer::startingDpdkThreads()
{

    _workers_threads.emplace_back(new RxReceiverThread(_device1));
    _workers_threads.emplace_back(new RxSenderThread(_device2));
    _workers_threads.emplace_back(new TxReceiverThread(_device2));
    _workers_threads.emplace_back(new TxSenderThread(_device1));

    int workersCoreMask = 0;
    for (int i = 1; i <= CORES_TO_USE; i++)
    {
        workersCoreMask = workersCoreMask | (1 << i);
    }

    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, _workers_threads))
    {
        throw std::runtime_error("Couldn't start worker threads\n");
    }
}

void PacketSniffer::closeDevices()
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


PacketSniffer::PacketSniffer(): _device1(nullptr), _device2(nullptr)
{
    _keep_running = true;
    try {
        openDpdkDevices();
        printDeviceInfo();
        startingDpdkThreads();
    }
    catch (const std::exception& e) {
        std::cerr << "Exception:" << e.what()<< std::endl;
    }
}

PacketSniffer::~PacketSniffer()
{
    for (const auto* thread : _workers_threads) {
        delete thread;
    }
    _workers_threads.clear();
    closeDevices();
}