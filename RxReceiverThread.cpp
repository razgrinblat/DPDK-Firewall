#include "RxReceiverThread.hpp"


RxReceiverThread::RxReceiverThread(pcpp::DpdkDevice *rx_device) :
_rx_device1(rx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1)
{
}

bool RxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    QueuesManager& queues_manager = QueuesManager::getInstance();
    PacketStats& packet_stats = PacketStats::getInstance();
    while (!_stop)
    {
        const uint32_t num_of_packets = _rx_device1->receivePackets(mbuf_array.data(),MAX_RECEIVE_BURST,0);
        if (num_of_packets > 0)
        {
            for(uint32_t i =0; i<num_of_packets; i++)
            {
                pcpp::Packet parsed_packet(mbuf_array[i]);
                packet_stats.consumePacket(parsed_packet);
            }
            {
                std::lock_guard<std::mutex> lock_guard(queues_manager.getRxQueueMutex());
                for(uint32_t i =0; i<num_of_packets; i++)
                {
                    queues_manager.getRxQueue()->push(mbuf_array[i]);
                }
            }
        }
    }
    for (int i = 0; i < MAX_RECEIVE_BURST; i++)
    {
        if (mbuf_array[i] != nullptr)
            delete mbuf_array[i];
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
