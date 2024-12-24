#pragma once
#include <functional>
#include <sys/inotify.h>
#include <unistd.h>
#include <thread>
#include <iostream>
#include <atomic>

class InotifyWrapper
{

public:
    InotifyWrapper();
    ~InotifyWrapper();
    void startWatching();

    void addWatch(const std::string& file_name, const std::function<void()> &callback);

private:

    static constexpr auto BUFFER_SIZE = sizeof(struct inotify_event);
    int _inotify_fd;
    int _watch_descriptor;
    std::thread _event_thread;
    std::function<void()> _callback;
    std::atomic<bool> _running;

    void eventLoop();
    void processEvent(std::array<char,BUFFER_SIZE>& event_buffer);

};


