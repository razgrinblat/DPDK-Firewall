#include "TxSenderThread.hpp"

void TxSenderThread::fetchPacketsFromTx(uint32_t& packets_to_send)
{
    std::lock_guard lock_guard(_queues_manager.getTxQueueMutex());
    packets_to_send = std::min(Config::MAX_RECEIVE_BURST,static_cast<int>(_queues_manager.getTxQueue()->size()));

    for(int i = 0; i < packets_to_send; ++i)
    {
        _mbuf_array[i] = _queues_manager.getTxQueue()->front();
        _queues_manager.getTxQueue()->pop();
    }
}

void TxSenderThread::processPackets(const uint32_t& packets_to_send)
{
    for(int i = 0; i < packets_to_send; ++i)
    {
        //change every mbuf src MAC and src IP before forwarding to client
        pcpp::Packet parsed_packet(_mbuf_array[i]);
        pcpp::EthLayer* eth_layer = parsed_packet.getLayerOfType<pcpp::EthLayer>();
        if(eth_layer != nullptr) // set to dpdk device1 MAC
        {
            eth_layer->setSourceMac(Config::DPDK_DEVICE1_MAC_ADDRESS);
            eth_layer->setDestMac(Config::CLIENT_MAC_ADDRESS); //client MAC
        }
        pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>(); //set to dpdk device1 IP address
        if(ipv4_layer != nullptr)
        {
            ipv4_layer->setDstIPv4Address(Config::CLIENT_IP);
            parsed_packet.computeCalculateFields();
        }
    }
}

TxSenderThread::TxSenderThread(pcpp::DpdkDevice *tx_device): _tx_device2(tx_device), _stop(true),
                                                             _coreId(MAX_NUM_OF_CORES + 1), _mbuf_array{},
                                                             _queues_manager(QueuesManager::getInstance()) {
}

bool TxSenderThread::run(uint32_t coreId)
{
     _coreId = coreId;
    _stop = false;
    uint32_t packets_to_send = 0;

    while (!_stop)
    {
        fetchPacketsFromTx(packets_to_send);

        if (packets_to_send > 0)
        {
            processPackets(packets_to_send);
            _tx_device2->sendPackets(_mbuf_array.data(),packets_to_send,0);
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