#include "QueuesManager.hpp"

QueuesManager::QueuesManager()
{
    _rx_queue = std::make_shared<std::queue<pcpp::MBufRawPacket*>>();
    _tx_queue = std::make_shared<std::queue<pcpp::MBufRawPacket*>>();
}

QueuesManager & QueuesManager::getInstance()
{
    static QueuesManager instance; // Single instance created on first call
    return instance;
}

std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> QueuesManager::getRxQueue()
{
    return _rx_queue;
}

std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> QueuesManager::getTxQueue()
{
    return _tx_queue;
}

std::mutex& QueuesManager::getRxQueueMutex()
{
    return _rx_queue_mutex;
}

std::mutex & QueuesManager::getTxQueueMutex()
{
    return _tx_queue_mutex;
}
