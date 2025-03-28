#include "PacketSniffer.hpp"

void PacketSniffer::buildFirewallRules() const {
    _http_rules_handler.buildRules();
    _rule_tree.buildTree();
}

void PacketSniffer::openDpdkDevices()
{
    pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterruptedCallBack, &_keep_running);

    const pcpp::CoreMask core_mask_to_use = pcpp::getCoreMaskForAllMachineCores();
    pcpp::DpdkDeviceList::initDpdk(core_mask_to_use,Config::MBUF_POOL_SIZE);

    _device1 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_1);
    _device2 = pcpp::DpdkDeviceList::getInstance().getDeviceByPort(Config::DPDK_DEVICE_2);

    if(_device1 == nullptr || !_device1->open())
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(Config::DPDK_DEVICE_1) + "'\n");
    }
    if(_device2 == nullptr || !_device2->open())
    {
        throw std::runtime_error("Cannot find device with port '" + std::to_string(Config::DPDK_DEVICE_2) + "'\n");
    }
}

void PacketSniffer::onApplicationInterruptedCallBack(void* cookie)
{
     bool* keep_running = static_cast<bool*>(cookie);

    *keep_running = false;
    std::cout << std::endl << "Shutting down..." << std::endl;
}

void PacketSniffer::startingDpdkThreads()
{

    _workers_threads.emplace_back(new RxReceiverThread(_device1));
    _workers_threads.emplace_back(new RxSenderThread(_device2));
    _workers_threads.emplace_back(new TxReceiverThread(_device2));
    _workers_threads.emplace_back(new TxSenderThread(_device1));

    int workersCoreMask = 0;
    for (int i = 1; i <= Config::CORES_TO_USE; i++)
    {
        workersCoreMask = workersCoreMask | (1 << i);
    }

    if (!pcpp::DpdkDeviceList::getInstance().startDpdkWorkerThreads(workersCoreMask, _workers_threads))
    {
        throw std::runtime_error("Couldn't start worker threads\n");
    }
}

void PacketSniffer::startingWsThreads()
{
    _ws_client.start("ws://192.168.1.33:8080/firewall");
    _ws_manager_thread = std::thread(&PacketSniffer::runWsManagerThread,this);
}

void PacketSniffer::runWsManagerThread()
{
    while (_keep_running)
    {
        _packet_stats.sendPacketStatsToBackend();
        _session_table.sendTableToBackend();
        std::this_thread::sleep_for(std::chrono::seconds(1));
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

PacketSniffer::PacketSniffer(): _device1(nullptr), _device2(nullptr), _keep_running(true),
_rule_tree(RuleTree::getInstance()),_http_rules_handler(HttpRulesHandler::getInstance()), _ws_client(WebSocketClient::getInstance()),
_packet_stats(PacketStats::getInstance()), _arp_handler(ArpHandler::getInstance()), _session_table(SessionTable::getInstance()),
_clients_manager(ClientsManager::getInstance()), _port_allocator(PortAllocator::getInstance())
{
    buildFirewallRules();
    openDpdkDevices();
    startingDpdkThreads();
    startingWsThreads();
}

PacketSniffer::~PacketSniffer()
{
    if (_ws_manager_thread.joinable())
    {
        _ws_manager_thread.join();
    }
    pcpp::DpdkDeviceList::getInstance().stopDpdkWorkerThreads();
    for (const auto* thread : _workers_threads) {
        delete thread;
    }
    closeDevices();
}

void PacketSniffer::startingCapture()
{
    std::cout << "starting capturing packets...\n";

    std::string user_input;
    std::cout << "------------------------------\n";
    std::cout << "Enter 'arp' to view ARP cache,'p' to view packet stats, 'tcp' to view TCP session cache or 'exit' to stop:\n";
    std::cout << "------------------------------\n";
    while (_keep_running)
    {
        std::getline(std::cin, user_input);
        std::cout << "------------------------------\n";
        if (user_input == "arp")
        {
            _arp_handler.printArpCache();
        }
        else if (user_input == "clients")
        {
            _clients_manager.printClientsTable();
        }
        else if(user_input == "port")
        {
            _port_allocator.printPortsTable();
        }
        else if (user_input == "p")
        {
            std::cout << "Displaying Packet Statistics:\n";
            _packet_stats.printToConsole();
        }
        else if (user_input == "tcp")
        {
            _session_table.printSessionCache();
        }
        else if(user_input == "exit")
        {
            _keep_running = false;
        }
        else
        {
            std::cout << "Invalid input. Please try again.\n";
        }
    }
}