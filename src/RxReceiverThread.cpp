#include "RxReceiverThread.hpp"

void RxReceiverThread::pushPacketToQueue(std::vector<pcpp::MBufRawPacket *> &packets_to_queue) const
{
    if (!packets_to_queue.empty())
    {
        std::lock_guard lock(_queues_manager.getRxQueueMutex());
        for (auto* packet : packets_to_queue)
        {
            _rx_queue->push(packet);
        }
    }
}

RxReceiverThread::RxReceiverThread(pcpp::DpdkDevice *rx_device) : _rx_device1(rx_device), _stop(true),
                                                                  _coreId(MAX_NUM_OF_CORES + 1),
                                                                  _queues_manager(QueuesManager::getInstance()),
                                                                  _rule_tree(RuleTree::getInstance()),
                                                                  _arp_handler(ArpHandler::getInstance()),
                                                                  _icmp_handler(IcmpHandler::getInstance()),
                                                                  _packet_stats(PacketStats::getInstance()),
                                                                  _clients_manager(ClientsManager::getInstance())
{
    _rx_queue = _queues_manager.getRxQueue();
}

bool RxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;

    std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST> mbuf_array= {};
    std::vector<pcpp::MBufRawPacket*> packets_to_queue(Config::MAX_RECEIVE_BURST);

    while (!_stop)
    {
        packets_to_queue.clear();
        const uint32_t number_of_packets = _rx_device1->receivePackets(mbuf_array.data(),Config::MAX_RECEIVE_BURST,0);

        for(uint32_t i = 0; i < number_of_packets; ++i)
        {
            pcpp::Packet parsed_packet(mbuf_array[i]);
            _clients_manager.processClientPacket(parsed_packet);
            _packet_stats.consumePacket(parsed_packet);
            if (parsed_packet.isPacketOfType(pcpp::ARP)) // handle ARP requests from clients
            {
                // sending ARP responses back to client
                const pcpp::ArpLayer* arp_layer = parsed_packet.getLayerOfType<pcpp::ArpLayer>();
                _arp_handler.sendArpResponsePacket(arp_layer->getSenderIpAddr(), arp_layer->getSenderMacAddress(), Config::DPDK_DEVICE_1);
            }
            else if (parsed_packet.isPacketOfType(pcpp::ICMP) && _icmp_handler.processOutBoundIcmp(parsed_packet))
            {
                packets_to_queue.push_back(mbuf_array[i]);
            }
            else if (parsed_packet.isPacketOfType(pcpp::TCP) || parsed_packet.isPacketOfType(pcpp::UDP))
            {
                if(_rule_tree.handleOutboundForwarding(parsed_packet))
                {
                    packets_to_queue.push_back(mbuf_array[i]);
                }
                else
                {
                    FirewallLogger::getInstance().packetDropped(parsed_packet.toString());
                }
            }
        }
        // Lock the queue and push all packets in a batch
        pushPacketToQueue(packets_to_queue);
    }
    return true;
}

void RxReceiverThread::stop()
{
    _stop = true;
}

uint32_t RxReceiverThread::getCoreId() const
{
    return _coreId;
}
