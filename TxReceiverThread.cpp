#include "TxReceiverThread.hpp"

void TxReceiverThread::pushToTxQueue()
{
    if (!_packets_to_client.empty())
    {
        {
            std::lock_guard lock_guard(_queues_manager.getTxQueueMutex());
            for(const auto& packet : _packets_to_client)
            {
                _queues_manager.getTxQueue()->push(packet);
            }
        }
    }
}

void TxReceiverThread::processReceivedPackets(std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST>& mbuf_array)
{
    const uint32_t num_of_packets = _tx_device1->receivePackets(mbuf_array.data(),MAX_RECEIVE_BURST,0);
    _packets_to_client.clear();
    for (int i = 0; i < num_of_packets; ++i)
    {
        processSinglePacket(mbuf_array[i]);
    }
}

void TxReceiverThread::processSinglePacket(pcpp::MBufRawPacket *raw_packet)
{
    pcpp::Packet parsed_packet(raw_packet);
    auto eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
    if(eth_layer && (eth_layer->getDestMac() == DPDK_DEVICE2_MAC_ADDRESS || eth_layer->getDestMac() == BROADCAST_MAC_ADDRESS))
    {
        _packet_stats.consumePacket(parsed_packet);
        if(parsed_packet.isPacketOfType(pcpp::ARP))
        {
            const pcpp::ArpLayer* arp_layer = parsed_packet.getLayerOfType<pcpp::ArpLayer>();
            _arp_handler.handleReceivedArpPacket(*arp_layer);
        }
        else
        {
            if (parsed_packet.isPacketOfType(pcpp::TCP))
            {
                if (_session_handler.processInternetTcpPacket(&parsed_packet))
                {
                    _packets_to_client.push_back(raw_packet);
                }
            }
            else
            {
                _packets_to_client.push_back(raw_packet);
            }
        }
    }
}

TxReceiverThread::TxReceiverThread(pcpp::DpdkDevice *tx_device) : _tx_device1(tx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1),
                                                                  _queues_manager(QueuesManager::getInstance()), _arp_handler(ArpHandler::getInstance()),
                                                                  _packet_stats(PacketStats::getInstance()), _session_handler(TcpSessionHandler::getInstance())
{
}

bool TxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;

    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    _packets_to_client.reserve(MAX_RECEIVE_BURST);

    while (!_stop)
    {
        processReceivedPackets(mbuf_array);
        pushToTxQueue(); // Pushing packets that are intended for the client
    }
    return true;
}

void TxReceiverThread::stop()
{
    _stop = true;
}

uint32_t TxReceiverThread::getCoreId() const
{
    return _coreId;
}