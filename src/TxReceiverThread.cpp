#include "TxReceiverThread.hpp"

void TxReceiverThread::pushPacketToQueue(std::vector<pcpp::MBufRawPacket *> &packets_to_queue) const
{
    if (!packets_to_queue.empty())
    {
        std::lock_guard lock(_queues_manager.getTxQueueMutex());
        for (auto* packet : packets_to_queue)
        {
            _tx_queue->push(packet);
        }
    }
}

TxReceiverThread::TxReceiverThread(pcpp::DpdkDevice *tx_device) : _tx_device1(tx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1),
                                                                  _queues_manager(QueuesManager::getInstance()),
                                                                  _rule_tree(RuleTree::getInstance()),
                                                                  _arp_handler(ArpHandler::getInstance()),
                                                                  _icmp_handler(IcmpHandler::getInstance()),
                                                                  _packet_stats(PacketStats::getInstance())
{
    _tx_queue = _queues_manager.getTxQueue();
}

bool TxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;

    std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST> mbuf_array= {};
    std::vector<pcpp::MBufRawPacket*> packets_to_queue(Config::MAX_RECEIVE_BURST);

    while (!_stop)
    {
        packets_to_queue.clear();
        const uint32_t num_of_packets = _tx_device1->receivePackets(mbuf_array.data(),Config::MAX_RECEIVE_BURST,0);

        for (uint32_t i = 0; i < num_of_packets; ++i)
        {
            pcpp::Packet parsed_packet(mbuf_array[i]);
            const auto eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
            if(eth_layer && (eth_layer->getDestMac() == Config::DPDK_DEVICE2_MAC_ADDRESS || eth_layer->getDestMac() == Config::BROADCAST_MAC_ADDRESS))
            {
                _packet_stats.consumePacket(parsed_packet);
                if (parsed_packet.isPacketOfType(pcpp::ARP))
                {
                    const pcpp::ArpLayer* arp_layer = parsed_packet.getLayerOfType<pcpp::ArpLayer>();
                    _arp_handler.handleReceivedArpPacket(*arp_layer);
                }
                else if (parsed_packet.isPacketOfType(pcpp::ICMP) && _icmp_handler.processInBoundIcmp(parsed_packet))
                {
                    packets_to_queue.push_back(mbuf_array[i]);
                }
                else if(parsed_packet.isPacketOfType(pcpp::TCP) || parsed_packet.isPacketOfType(pcpp::UDP))
                {
                    packets_to_queue.push_back(mbuf_array[i]);
                }
            }
        }
        // Lock the queue and push all packets in a batch
        pushPacketToQueue(packets_to_queue);
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