#include "TxReceiverThread.hpp"

TxReceiverThread::TxReceiverThread(pcpp::DpdkDevice *tx_device) : _tx_device1(tx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1)
{
}

bool TxReceiverThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    std::vector<pcpp::MBufRawPacket*> valid_packets;
    valid_packets.reserve(MAX_RECEIVE_BURST);
    QueuesManager& queues_manager = QueuesManager::getInstance();
    ArpHandler& arp_handler = ArpHandler::getInstance();
    PacketStats& packet_stats = PacketStats::getInstance();
    pcpp::MacAddress device_mac(_tx_device1->getMacAddress());
    while (!_stop)
    {
        const uint32_t num_of_packets = _tx_device1->receivePackets(mbuf_array.data(),MAX_RECEIVE_BURST,0);
        valid_packets.clear();
        for(int i=0; i<num_of_packets; i++)
        {
            pcpp::Packet parsed_packet(mbuf_array[i]);
            pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
            if(eth_layer != nullptr) {
                pcpp::MacAddress dest_mac = eth_layer->getDestMac();
                if(dest_mac == device_mac || dest_mac == BROADCAST_MAC_ADDRESS)
                {
                    packet_stats.consumePacket(parsed_packet);
                    if(parsed_packet.isPacketOfType(pcpp::ARP)) {
                        pcpp::ArpLayer* arp_layer = parsed_packet.getLayerOfType<pcpp::ArpLayer>();
                        arp_handler.handleReceivedArpPacket(*arp_layer);
                    }
                    else {
                        valid_packets.push_back(mbuf_array[i]);
                    }
                }
            }
        }
        if (!valid_packets.empty())
        {
            {
                std::lock_guard<std::mutex> lock_guard(queues_manager.getTxQueueMutex());
                for(const auto& packet : valid_packets)
                {
                    queues_manager.getTxQueue()->push(packet);
                }
            }
        }
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
