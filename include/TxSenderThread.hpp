#pragma once
#include <DpdkDeviceList.h>
#include "QueuesManager.hpp"
#include "TcpSessionHandler.hpp"
#include "PortAllocator.hpp"
#include "ClientsManager.hpp"
#include "IcmpHandler.hpp"
#include "UdpSessionHandler.hpp"

class TxSenderThread : public pcpp::DpdkWorkerThread
{
private:
    pcpp::DpdkDevice* _tx_device2;
    bool _stop;
    uint32_t _coreId;
    QueuesManager& _queues_manager;
    TcpSessionHandler& _tcp_session_handler;
    UdpSessionHandler& _udp_session_handler;
    PortAllocator& _port_allocator;
    ClientsManager& _client_manager;
    IcmpHandler& _icmp_handler;
    std::vector<pcpp::MBufRawPacket*> _packets_to_process;

    void fetchPacketsFromTx();
    void modifyUdpPacket(const pcpp::Packet& parsed_packet, const pcpp::IPv4Address& client_ipv4, uint16_t client_port);
    void modifyTcpPacket(const pcpp::Packet& parsed_packet, const pcpp::IPv4Address& client_ipv4, uint16_t client_port);
    void modifyPacketHeaders(pcpp::Packet& parsed_packet);
    void sendPackets(std::array<pcpp::MBufRawPacket*, Config::MAX_RECEIVE_BURST> &packet_buffer, uint32_t packets_number);

public:
    TxSenderThread(pcpp::DpdkDevice* tx_device);
    ~TxSenderThread() = default;

    bool run(uint32_t coreId) override;

    void stop() override;

    uint32_t getCoreId() const override;
};



