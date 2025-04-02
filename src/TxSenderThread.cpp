#include "TxSenderThread.hpp"

void TxSenderThread::fetchPacketsFromTx()
{
    std::lock_guard lock(_queues_manager.getTxQueueMutex());
    const auto tx_queue = _queues_manager.getTxQueue();
    const uint32_t packets_to_send = std::min(Config::MAX_RECEIVE_BURST,static_cast<int>(tx_queue->size()));

    for(int i = 0; i < packets_to_send; ++i)
    {
        _packets_to_process.push_back(tx_queue->front());
        tx_queue->pop();
    }
}

void TxSenderThread::modifyUdpPacket(const pcpp::Packet &parsed_packet, const pcpp::IPv4Address &client_ipv4,
                                     const uint16_t client_port)
{
    pcpp::udphdr* udphdr = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader();
    udphdr->portDst = pcpp::hostToNet16(client_port); // set to client dst port

    pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    ipv4_layer->setDstIPv4Address(client_ipv4); // set to client dst ip

    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    eth_layer->setSourceMac(Config::DPDK_DEVICE1_MAC_ADDRESS); //set source mac to DPDK1 device
    eth_layer->setDestMac(_client_manager.getClientMacAddress(client_ipv4)); // set to client dst mac
}

void TxSenderThread::modifyTcpPacket(const pcpp::Packet &parsed_packet, const pcpp::IPv4Address &client_ipv4,
                                     const uint16_t client_port)
{
    pcpp::tcphdr* tcphdr = parsed_packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader();
    tcphdr->portDst = pcpp::hostToNet16(client_port); // set to client dst port

    pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    ipv4_layer->setDstIPv4Address(client_ipv4); // set to client dst ip

    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    eth_layer->setSourceMac(Config::DPDK_DEVICE1_MAC_ADDRESS); //set source mac to DPDK1 device
    eth_layer->setDestMac(_client_manager.getClientMacAddress(client_ipv4)); // set to client dst mac
}

void TxSenderThread::modifyPacketHeaders(pcpp::Packet& parsed_packet)
{
    if (parsed_packet.isPacketOfType(pcpp::TCP))
    {
        pcpp::tcphdr* tcphdr = parsed_packet.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader();
        if (const auto& result = _port_allocator.getClientIpAndPort(pcpp::netToHost16(tcphdr->portDst)))
        {
            const auto& [client_ip, client_port] = result.value();
            modifyTcpPacket(parsed_packet,client_ip,client_port);
        }
        else {
            throw std::runtime_error("un valid incoming TCP packet: " + parsed_packet.toString());
        }
    }
    else if (parsed_packet.isPacketOfType(pcpp::UDP))
    {
        pcpp::udphdr* udphdr = parsed_packet.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader();
        if (const auto& result = _port_allocator.getClientIpAndPort(pcpp::netToHost16(udphdr->portDst)))
        {
            const auto& [client_ip, client_port] = result.value();
            modifyUdpPacket(parsed_packet, client_ip,client_port);
        }
        else {
            throw std::runtime_error("un valid incoming UDP packet: " + parsed_packet.toString());
        }
    }
    parsed_packet.computeCalculateFields();
}

void TxSenderThread::sendPackets(std::array<pcpp::MBufRawPacket *, Config::MAX_RECEIVE_BURST> &packet_buffer,
    const uint32_t packets_number)
{
    if (packets_number > 0)
    {
        _tx_device2->sendPackets(packet_buffer.data(),packets_number,0);
    }
}

TxSenderThread::TxSenderThread(pcpp::DpdkDevice *tx_device): _tx_device2(tx_device), _stop(true),
                                                             _coreId(MAX_NUM_OF_CORES + 1), _queues_manager(QueuesManager::getInstance()),
                                                             _tcp_session_handler(TcpSessionHandler::getInstance()), _udp_session_handler(UdpSessionHandler::getInstance()),
                                                             _port_allocator(PortAllocator::getInstance()), _client_manager(ClientsManager::getInstance()),
                                                             _packets_to_process(Config::MAX_RECEIVE_BURST)
{}

bool TxSenderThread::run(uint32_t coreId)
{
     _coreId = coreId;
    _stop = false;

    std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST> mbuf_array= {};

    while (!_stop)
    {
        _packets_to_process.clear();
        fetchPacketsFromTx();

        uint32_t packets_to_send = 0;
        for (auto* raw_packet : _packets_to_process)
        {
            pcpp::Packet parsed_packet(raw_packet);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) && parsed_packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address() == Config::DPDK_DEVICE2_IP)
            {
                try {
                    modifyPacketHeaders(parsed_packet);
                    if (parsed_packet.isPacketOfType(pcpp::TCP))
                    {
                        _tcp_session_handler.isValidInternetTcpPacket(parsed_packet);
                    }
                    else if (parsed_packet.isPacketOfType(pcpp::UDP))
                    {
                        _udp_session_handler.isValidInternetUdpPacket(parsed_packet);
                    }
                    mbuf_array[packets_to_send++] = raw_packet;
                }
                catch (const std::exception& e) { // packet is blocked or unvalid
                    std::cerr << e.what() << std::endl;
                }
            }
        }
        sendPackets(mbuf_array,packets_to_send);
    }
    return true;
}

void TxSenderThread::stop()
{
    _stop = true;
}

uint32_t TxSenderThread::getCoreId() const
{
    return _coreId;
}