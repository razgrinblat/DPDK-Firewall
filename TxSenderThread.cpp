#include "TxSenderThread.hpp"

TxSenderThread::TxSenderThread(pcpp::DpdkDevice *tx_device):
_tx_device2(tx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1)
{
}

bool TxSenderThread::run(uint32_t coreId)
{
     _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    uint32_t packets_to_send = 0;
     const pcpp::MacAddress device_mac(_tx_device2->getMacAddress());
    QueuesManager& queues_manager = QueuesManager::getInstance();
    while (!_stop)
    {
        {
            std::lock_guard<std::mutex> lock_guard(queues_manager.getTxQueueMutex());
            packets_to_send = std::min(MAX_RECEIVE_BURST,static_cast<int>(queues_manager.getTxQueue()->size()));

            for(int i = 0; i < packets_to_send; i++)
            {
                mbuf_array[i] = queues_manager.getTxQueue()->front();
                queues_manager.getTxQueue()->pop();
            }
        }
        if (packets_to_send > 0)
        {
            for(int i=0; i<packets_to_send; i++)
            {
                //change every mbuf src mac and src ip before forwarding to client
                pcpp::Packet parsed_packet(mbuf_array[i]);
                pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
                if(eth_layer != nullptr)
                {
                    eth_layer->setSourceMac(device_mac);
                    eth_layer->setDestMac(CLIENT_MAC_ADDRESS); //client MAC
                }
                pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if(ipv4_layer != nullptr)
                {
                    ipv4_layer->setDstIPv4Address(CLIENT_IP);
                    parsed_packet.computeCalculateFields();
                }
            }
            _tx_device2->sendPackets(mbuf_array.data(),packets_to_send,0);
        }
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
