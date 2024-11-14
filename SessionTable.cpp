#include "SessionTable.hpp"
#include <thread>

SessionTable::SessionTable(): _lru_list(MAX_SESSIONS),_stop_flag(true)
{
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread, this);
}

void SessionTable::cleanUpIdleSessions()
{
    const auto current_time = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock_guard(_cache_mutex);
    for (auto it = _session_cache.begin() ; it !=_session_cache.end();)
    {
        const std::unique_ptr<TcpSession> session = std::move(it->second);
        const auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(current_time - session->last_active_time).count();
        if(time_diff >= MAX_IDLE_SESSION_TIME)
        {
            _session_cache.erase(it->first);
            _lru_list.eraseElement(it->first);
        }
        else {
            break;
        }
    }
}

SessionTable::~SessionTable()
{
    _stop_flag.store(false);
    if (_clean_up_thread.joinable()) {
        _clean_up_thread.join();
    }
    _session_cache.clear();
}

SessionTable& SessionTable::getInstance()
{
    static SessionTable instance;
    return instance;
}

void SessionTable::runCleanUpThread()
{
    while (_stop_flag.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(CLEANUP_IDLE_SESSIONS_TIME));
        cleanUpIdleSessions();
    }
}

bool SessionTable::isSessionExists(const uint32_t session_hash)
{
    std::lock_guard<std::mutex> lock_guard(_cache_mutex);
    const auto it = _session_cache.find(session_hash);
    return it != _session_cache.end();
}

bool SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<TcpSession> session, const TcpState& current_state)
{
    if(!isSessionExists(session_hash))
    {
        uint32_t session_key_to_close;
        {
            std::lock_guard<std::mutex> lock_guard(_cache_mutex);
            const int result = _lru_list.put(session_hash,&session_key_to_close);
            if(result == 1)
            {
                _session_cache.erase(session_key_to_close); //session cache is full. need to delete the least active connection
            }
            session->last_active_time = std::chrono::steady_clock::now();
            session->current_state = current_state;
            _session_cache[session_hash] = std::unique_ptr<TcpSession>(std::move(session));
        }
        return true;
    }
    return false;
}

bool SessionTable::closeSession(const uint32_t session_hash)
{
    if(isSessionExists(session_hash))
    {
        {
            std::lock_guard<std::mutex> lock_guard(_cache_mutex);
            _session_cache.erase(session_hash);
            _lru_list.eraseElement(session_hash);
        }
        return true;
    }
    return false;

}

TcpState& SessionTable::getCurrentState(const uint32_t session_hash)
{
    if(isSessionExists(session_hash)) {
        std::lock_guard<std::mutex> lock_guard(_cache_mutex);
        return _session_cache[session_hash]->current_state;
    }
}

void SessionTable::updateSession(const uint32_t session_hash, const TcpState& new_state)
{
    if(isSessionExists(session_hash)) {
        std::lock_guard<std::mutex> lock_guard(_cache_mutex);
        _session_cache[session_hash]->current_state = new_state;
    }
}
