#pragma once
#include "RxReceiverThread.hpp"
#include "RxSenderThread.hpp"
#include "TxReceiverThread.hpp"
#include "TxSenderThread.hpp"
#include "WebSocketClient.hpp"

class PacketSniffer
{
private:
    pcpp::DpdkDevice* _device1;
    pcpp::DpdkDevice* _device2;
    std::vector<pcpp::DpdkWorkerThread*> _workers_threads;
    bool _keep_running;
    RuleTree& _rule_tree;
    HttpRulesHandler& _http_rules_handler;
    WebSocketClient& _ws_client;
    std::thread _ws_manager_thread;

    PacketStats& _packet_stats;
    ArpHandler& _arp_handler;
    SessionTable& _session_table;
    ClientsManager& _clients_manager;
    PortAllocator& _port_allocator;


    void buildFirewallRules() const;
    void openDpdkDevices();
    static void onApplicationInterruptedCallBack(void* cookie);
    void startingDpdkThreads();
    void startingWsThreads();
    void runWsManagerThread();
    void closeDevices();

public:
    PacketSniffer();
    ~PacketSniffer();

    void startingCapture();

};