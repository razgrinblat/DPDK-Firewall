#include "RxSenderThread.hpp"

#include "ArpHandler.hpp"

RxSenderThread::RxSenderThread(pcpp::DpdkDevice *rx_device) :
_rx_device2(rx_device), _stop(true), _coreId(MAX_NUM_OF_CORES+1)
{
}

bool RxSenderThread::run(uint32_t coreId)
{
    _coreId = coreId;
    _stop = false;
    std::array<pcpp::MBufRawPacket*,MAX_RECEIVE_BURST> mbuf_array= {};
    std::vector<pcpp::MBufRawPacket*> packets_to_process;
    pcpp::MacAddress device_mac(_rx_device2->getMacAddress());
    QueuesManager& queues_manager = QueuesManager::getInstance();
    ArpHandler& arp_handler = ArpHandler::getInstance();
    while (!_stop)
    {
        packets_to_process.clear();
        {
            std::lock_guard<std::mutex> lock_guard(queues_manager.getRxQueueMutex());
            for (int i = 0; i < MAX_RECEIVE_BURST && !queues_manager.getRxQueue()->empty(); ++i)
            {
                packets_to_process.push_back(queues_manager.getRxQueue()->front());
                queues_manager.getRxQueue()->pop();
            }
        }

        uint32_t packets_to_send = 0;
        for(auto* raw_packet : packets_to_process)
        {
            pcpp::Packet parsed_packet(raw_packet);
            pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
            if(ipv4_layer) {
                pcpp::IPv4Address dest_ip = ipv4_layer->getDstIPv4Address();

                if(isLocalNetworkPacket(dest_ip,ROUTER_IP,SUBNET_MASK))
                {
                    pcpp::MacAddress dest_mac = arp_handler.getMacAddress(dest_ip);
                    if (dest_mac == pcpp::MacAddress::Zero)
                    {
                        // MAC not resolved, initiate ARP request if not already pending with new thread
                        arp_handler.sendArpRequest(dest_ip);
                        continue; // Skip this packet until ARP is resolved
                    }
                    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
                    if(eth_layer)
                    {
                        eth_layer->setSourceMac(device_mac);
                        eth_layer->setDestMac(dest_mac);
                    }
                    ipv4_layer->setSrcIPv4Address(DPDK_DEVICE2_IP);
                    ipv4_layer->computeCalculateFields();
                }
                else
                {
                    pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
                    if(eth_layer)
                    {
                        eth_layer->setSourceMac(device_mac);
                        eth_layer->setDestMac(ROUTER_MAC_ADDRESS);
                    }
                    ipv4_layer->setSrcIPv4Address(DPDK_DEVICE2_IP);
                    ipv4_layer->computeCalculateFields();
                }
                mbuf_array[packets_to_send++] = raw_packet;
            }
        }
        if (packets_to_send > 0) {
            _rx_device2->sendPackets(mbuf_array.data(), packets_to_send);
        }
    }
    //clean the mbuf_array at exit
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

bool RxSenderThread::isLocalNetworkPacket(const pcpp::IPv4Address &dest_ip, const pcpp::IPv4Address &local_ip,
    const pcpp::IPv4Address &subnet_mask)
{
    uint32_t dest_network = dest_ip.toInt() & subnet_mask.toInt();
    uint32_t local_network = local_ip.toInt() & subnet_mask.toInt();

    return local_network == dest_network;
}
