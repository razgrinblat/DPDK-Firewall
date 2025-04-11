#include "RxSenderThread.hpp"

void RxSenderThread::fetchPacketFromRx()
{
    std::lock_guard lock_guard(_queues_manager.getRxQueueMutex());
    const auto rx_queue = _queues_manager.getRxQueue();
    const uint32_t packets_to_send = std::min(Config::MAX_RECEIVE_BURST,static_cast<int>(rx_queue->size()));

    for (int i = 0; i < packets_to_send ; ++i)
    {
        _packets_to_process.push_back(rx_queue->front());
        rx_queue->pop();
    }
}

void RxSenderThread::modifyPacketHeaders(pcpp::Packet &parsed_packet, const pcpp::MacAddress& dest_mac)
{
    pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    ipv4_layer->setSrcIPv4Address(Config::DPDK_DEVICE2_IP);

    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    eth_layer->setSourceMac(Config::DPDK_DEVICE2_MAC_ADDRESS);
    eth_layer->setDestMac(dest_mac);

    parsed_packet.computeCalculateFields();
}

bool RxSenderThread::resolveLocalNetworkPacket(const pcpp::IPv4Address &dest_ip)
{
    const pcpp::MacAddress dest_mac = _arp_handler.getMacAddress(dest_ip);
    if (dest_mac == pcpp::MacAddress::Zero)
    {
        // MAC not resolved, initiate ARP request if not already pending with new thread
        _arp_handler.sendArpRequest(dest_ip);
        return false; // Skip this packet until ARP is resolved
    }
    return true;
}

void RxSenderThread::sendPackets(std::array<pcpp::MBufRawPacket *, Config::MAX_RECEIVE_BURST> &packet_buffer,
    const uint32_t packets_number)
{
    if (packets_number > 0)
    {
        _rx_device2->sendPackets(packet_buffer.data(), packets_number,0);
    }
}

RxSenderThread::RxSenderThread(pcpp::DpdkDevice *rx_device) :
_rx_device2(rx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1), _queues_manager(QueuesManager::getInstance()),
_arp_handler(ArpHandler::getInstance()), _tcp_session_handler(TcpSessionHandler::getInstance()),
_udp_session_handler(UdpSessionHandler::getInstance()),
_packets_to_process(Config::MAX_RECEIVE_BURST)
{}

bool RxSenderThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;

    std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST> mbuf_array= {};

    while (!_stop)
    {
        _packets_to_process.clear();

        fetchPacketFromRx(); // fetch packets into _packets_to_process

        uint32_t packets_to_send = 0;
        for (auto* raw_packet : _packets_to_process)
        {
            pcpp::Packet parsed_packet(raw_packet);
            if (parsed_packet.isPacketOfType(pcpp::IPv4) && parsed_packet.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address() != Config::DPDK_DEVICE2_IP)
            {
                pcpp::MacAddress dest_mac;
                pcpp::IPv4Address dest_ip = parsed_packet.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();
                if (isLocalNetworkPacket(dest_ip,Config::ROUTER_IP,Config::SUBNET_MASK))
                {
                    if (!resolveLocalNetworkPacket(dest_ip))
                    {
                        continue; //continue if the packet ARP not resolved yet
                    }
                    dest_mac = _arp_handler.getMacAddress(dest_ip);
                }
                else
                {
                    dest_mac  = Config::ROUTER_MAC_ADDRESS;
                }
                try {
                    if (parsed_packet.isPacketOfType(pcpp::TCP))
                    {
                        _tcp_session_handler.processClientTcpPacket(parsed_packet);
                    }
                    else if (parsed_packet.isPacketOfType(pcpp::UDP))
                    {
                        _udp_session_handler.processClientUdpPacket(parsed_packet);
                    }
                    modifyPacketHeaders(parsed_packet,dest_mac);
                    mbuf_array[packets_to_send++] = raw_packet;
                }catch (const std::exception& e) {
                    std::cerr << e.what() << std::endl;
                }
            }
        }
        // Sends packets in bulk for efficiency
        sendPackets(mbuf_array,packets_to_send);
    }
    return true;
}

void RxSenderThread::stop()
{
    _stop = true;
}

uint32_t RxSenderThread::getCoreId() const
{
    return _coreId;
}