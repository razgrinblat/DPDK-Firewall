#include "RxSenderThread.hpp"

RxSenderThread::RxSenderThread(pcpp::DpdkDevice *rx_device) :
_rx_device2(rx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1)
{
}

bool RxSenderThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    uint32_t packets_to_send = 0;
    pcpp::MacAddress device_mac(_rx_device2->getMacAddress());
    QueuesManager& queues_manager = QueuesManager::getInstance();
    while (!_stop)
    {
        {
            std::lock_guard<std::mutex> lock_guard(queues_manager.getRxQueueMutex());
            for(int i=0; i<MAX_RECEIVE_BURST; i++)
            {
                 if(!queues_manager.getRxQueue()->empty())
                 {
                     mbuf_array[i] = queues_manager.getRxQueue()->front();
                     queues_manager.getRxQueue()->pop();
                     packets_to_send++;
                 }
                else
                {
                    break;
                }
            }
        }
        if (packets_to_send > 0)
        {
            for(int i=0; i<packets_to_send; i++)
            {
                //change every mbuf src mac and src ip before forwarding
                pcpp::Packet parsed_packet(mbuf_array[i]);
                pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
                if(eth_layer != nullptr)
                {
                    eth_layer->setSourceMac(device_mac);
                    eth_layer->setDestMac(ROUTER_MAC_ADDRESS); //router MAC address
                }
                pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
                if(ipv4_layer != nullptr)
                {
                    ipv4_layer->setSrcIPv4Address(DPDK_DEVICE2_IP); //DPDK DEVICE2 IP
                    ipv4_layer->computeCalculateFields();
                }
            }
            _rx_device2->sendPackets(mbuf_array.data(),packets_to_send,0);
            packets_to_send = 0;
        }
    }
    for (int i = 0; i < MAX_RECEIVE_BURST; i++)
    {
        if (mbuf_array[i] != nullptr)
            delete mbuf_array[i];
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
