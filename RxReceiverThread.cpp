#include "RxReceiverThread.hpp"

RxReceiverThread::RxReceiverThread(pcpp::DpdkDevice *rx_device) : _rx_device1(rx_device), _stop(true),
                                                                  _coreId(MAX_NUM_OF_CORES + 1),
                                                                  _queues_manager(QueuesManager::getInstance()),
                                                                  _rule_tree(RuleTree::getInstance()){}

bool RxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,Config::MAX_RECEIVE_BURST> mbuf_array= {};
    const auto rx_queue = _queues_manager.getRxQueue();
    while (!_stop)
    {
        const uint32_t num_of_packets = _rx_device1->receivePackets(mbuf_array.data(),Config::MAX_RECEIVE_BURST,0);
        if (num_of_packets > 0)
        {
            {
                std::lock_guard lock_guard(_queues_manager.getRxQueueMutex());
                for(uint32_t i = 0; i < num_of_packets; ++i)
                {
                    pcpp::Packet parsed_packet(mbuf_array[i]);
                    if(_rule_tree.handleOutboundForwarding(parsed_packet))
                    {
                        rx_queue->push(mbuf_array[i]);
                    }
                }
            }
        }
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
