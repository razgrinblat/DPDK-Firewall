#pragma once
#include "MBufRawPacket.h"
#include <queue>
#include <memory>
#include <mutex>

class QueuesManager
{
private:
    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> _rx_queue;
    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> _tx_queue;
    std::mutex _rx_queue_mutex;
    std::mutex _tx_queue_mutex;

    QueuesManager();

public:
    ~QueuesManager();
    QueuesManager(const QueuesManager&) = delete;
    QueuesManager& operator=(const QueuesManager&) = delete;
    static QueuesManager& getInstance();

    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> getRxQueue();
    std::shared_ptr<std::queue<pcpp::MBufRawPacket*>> getTxQueue();
    std::mutex& getRxQueueMutex();
    std::mutex& getTxQueueMutex();

    void clearQueue( std::shared_ptr<std::queue<pcpp::MBufRawPacket*>>& queue_ptr);

};
