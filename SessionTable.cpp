#include "SessionTable.hpp"

SessionTable::SessionTable(): _lru_list(Config::MAX_SESSIONS),_stop_flag(false)
{
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread,this);
}

void SessionTable::cleanUpIdleSessions()
{
    const auto current_time = std::chrono::high_resolution_clock::now();
    std::lock_guard lock_guard(_cache_mutex);
    for (auto it = _session_cache.begin() ; it !=_session_cache.end();)
    {
        const std::unique_ptr<TcpSession>& session = it->second;
        const auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(current_time - session->last_active_time).count();
        if(time_diff >= Config::MAX_IDLE_SESSION_TIME && session->current_state != ESTABLISHED)
        {
            _lru_list.eraseElement(it->first);
            it = _session_cache.erase(it);
        }
        else {
            ++it;
        }
    }
}

SessionTable::~SessionTable()
{
    _stop_flag.store(true);
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
    while (!_stop_flag.load())
    {
        cleanUpIdleSessions();
        std::this_thread::sleep_for(std::chrono::seconds(Config::CLEANUP_IDLE_SESSIONS_TIME)); // to avoid busy waiting
    }
}

bool SessionTable::isSessionExists(const uint32_t session_hash)
{
    std::lock_guard lock_guard(_cache_mutex);
    const auto it = _session_cache.find(session_hash);
    return it != _session_cache.end();
}

bool SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<TcpSession> session, const TcpState& current_state)
{
    if(!isSessionExists(session_hash))
    {
        uint32_t session_key_to_close;
        {
            std::lock_guard lock_guard(_cache_mutex);
            const int result = _lru_list.put(session_hash,&session_key_to_close);
            if(result)
            {
                _session_cache.erase(session_key_to_close); //session cache is full. need to delete the least active connection
            }
            session->last_active_time = std::chrono::high_resolution_clock::now();
            session->current_state = current_state;
            _session_cache[session_hash] = std::unique_ptr<TcpSession>(std::move(session));
        }
        return true;
    }
    return false;
}

const SessionTable::TcpState& SessionTable::getCurrentState(const uint32_t session_hash)
{
    if(isSessionExists(session_hash))
    {
        std::lock_guard lock_guard(_cache_mutex);
        return _session_cache[session_hash]->current_state;
    }
}

void SessionTable::updateSession(const uint32_t session_hash, const TcpState& new_state, uint32_t seq_number, uint32_t ack_number)
{
    if(isSessionExists(session_hash))
    {
        std::lock_guard lock_guard(_cache_mutex);
        _session_cache[session_hash]->current_state = new_state;
        _session_cache[session_hash]->current_ack = ack_number;
        _session_cache[session_hash]->current_seq = seq_number;
        _session_cache[session_hash]->last_active_time = std::chrono::high_resolution_clock::now();
    }
}

bool SessionTable::isDstIpInCache(const pcpp::IPv4Address &dst_ip_to_find)
{
    std::lock_guard lock_guard(_cache_mutex);
    for (const auto& [key, session] : _session_cache)
    {
        if (session->dst_ip == dst_ip_to_find)
        {
            return true;
        }
    }
    return false;
}

void SessionTable::printSessionCache()
{
    std::lock_guard lock_guard(_cache_mutex); // Ensure thread safety during access
    // Print the header
    std::cout << std::setw(15) << "State"
              << std::setw(20) << "Destination IP"
              << std::setw(15) << "Ports"
              << std::setw(30) << "Last Active Time" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    // Iterate through the session cache
    for (const auto& pair : _session_cache) {
        const TcpSession* session = pair.second.get();

        // Convert TcpState to string
        std::string state;
        switch (session->current_state) {
            case SYN_SENT:      state = "SYN_SENT"; break;
            case SYN_RECEIVED:  state = "SYN_RECEIVED"; break;
            case ESTABLISHED:   state = "ESTABLISHED"; break;
            case FIN_WAIT1:     state = "FIN_WAIT1"; break;
            case FIN_WAIT2:     state = "FIN_WAIT2"; break;
            case CLOSE_WAIT:    state = "CLOSE_WAIT"; break;
            case TIME_WAIT:     state = "TIME_WAIT"; break;
            case LAST_ACK:      state = "LAST_ACK";  break;
            default:            state = "UNKNOWN"; break;
        }

        // Convert `last_active_time` to HH:MM:SS format and print session details
        auto last_active_time = session->last_active_time;
        // Adjust high_resolution_clock to system_clock
        auto now_system_time = std::chrono::system_clock::now() +
                               (last_active_time - std::chrono::high_resolution_clock::now());
        std::time_t last_active_time_t = std::chrono::system_clock::to_time_t(now_system_time);
        // Format time to HH:MM:SS
        const std::tm* tm_info = std::localtime(&last_active_time_t);
        std::ostringstream time_stream;
        time_stream << std::put_time(tm_info, "%H:%M:%S");

        std::string port_info = std::to_string(session->source_port) + " -> " + std::to_string(session->dst_port);
        std::cout << std::setw(15) << state
                  << std::setw(20) << session->dst_ip.toString()
                  << std::setw(15) << port_info
                  << std::setw(20) << time_stream.str() << std::endl;
    }
    std::cout << "Total sessions: " << _session_cache.size() << std::endl;
}