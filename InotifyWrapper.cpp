#include "InotifyWrapper.hpp"


InotifyWrapper::InotifyWrapper() :_inotify_fd(-1), _watch_descriptor(-1), _running(false)
{
    _inotify_fd = inotify_init(); // blocking mode
    if (_inotify_fd < 0) {
        throw std::runtime_error("Failed to initialize inotify");
    }
}

InotifyWrapper::~InotifyWrapper()
{
    stopThread();
    if (_inotify_fd >= 0) {
        close(_inotify_fd);
    }
}

void InotifyWrapper::startWatching()
{
    _running.store(true);
    _event_thread = std::thread(&InotifyWrapper::eventLoop, this);
}

void InotifyWrapper::addWatch(const std::string &file_name, const std::function<void()> &callback)
{
    _watch_descriptor = inotify_add_watch(_inotify_fd, file_name.c_str(), IN_MODIFY);
    if(_watch_descriptor < 0) {
        throw std::runtime_error("Failed to add inotify watch for: " + file_name);
    }
    _callback = callback;

}

void InotifyWrapper::eventLoop()
{
    std::array<char,BUFFER_SIZE> event_buffer;
    while (_running.load())
    {
        int length = read(_inotify_fd, event_buffer.data(), event_buffer.size());
        if(length < 0)
        {
            throw std::runtime_error("Error reading inotify events");
        }
        processEvent(event_buffer);
    }
}

void InotifyWrapper::processEvent(std::array<char,BUFFER_SIZE>& event_buffer)
{
    auto event = reinterpret_cast<struct inotify_event*>(event_buffer.data());

    if (event->wd == _watch_descriptor && (event->mask & IN_MODIFY))
    {
        _callback(); // Invoke the callback for the modified file
    }
}

void InotifyWrapper::stopThread()
{
    _running.store(false);
    if(_event_thread.joinable())
    {
        _event_thread.join();
    }
}
