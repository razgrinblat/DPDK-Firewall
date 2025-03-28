#include "SessionTable.hpp"

SessionTable::SessionTable(): _lru_list(Config::MAX_SESSIONS), _stop_flag(false),
_port_allocator(PortAllocator::getInstance()), _ws_client(WebSocketClient::getInstance())
{
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread,this);
}

void SessionTable::cleanUpIdleSessions()
{
    const auto current_time = std::chrono::steady_clock::now();

    std::unique_lock lock(_cache_mutex);
    for (auto it = _session_cache.begin() ; it !=_session_cache.end();)
    {
        const std::unique_ptr<Session>& session = it->second;
        const auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(current_time - session->last_active_time).count();
        if(time_diff >= Config::MAX_IDLE_SESSION_TIME && (session->current_state != ESTABLISHED || session->isAllowed == false))
        {
            _port_allocator.releasePort(session->firewall_port);
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
    if (_clean_up_thread.joinable())
    {
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
    std::shared_lock lock(_cache_mutex);
    return _session_cache.find(session_hash) != _session_cache.end();
}

void SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<Session> session, const TcpState& current_state)
{
    std::unique_lock lock_guard(_cache_mutex);

    uint32_t session_key_to_close;
    const int result = _lru_list.put(session_hash,&session_key_to_close);
    if(result)
    {
        _session_cache.erase(session_key_to_close); //session cache is full. need to delete the least active connection
    }
    session->last_active_time = std::chrono::steady_clock::now();
    session->current_state = current_state;
    session->firewall_port = _port_allocator.allocatePort(session->source_ip, session->source_port);
    _session_cache[session_hash] = std::move(session);
}

const SessionTable::TcpState& SessionTable::getCurrentState(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) {
        return it->second->current_state;
    }
    throw std::runtime_error("Session " + std::to_string(session_hash) + " does not exist!");
}

uint16_t SessionTable::getFirewallPort(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) {
        return it->second->firewall_port;
    }
    throw std::runtime_error("Session " + std::to_string(session_hash) + " does not exist!");
}

void SessionTable::updateSession(const uint32_t session_hash, const TcpState& new_state)
{
    std::unique_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end())
    {
        it->second->current_state = new_state;
        it->second->last_active_time = std::chrono::steady_clock::now();
    }
    else
    {
        throw std::runtime_error("Session " + std::to_string(session_hash) + " does not exist!");
    }
}

bool SessionTable::isAllowed(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) {
        return it->second->isAllowed;
    }
    throw std::runtime_error("Session " + std::to_string(session_hash) + " does not exist!");
}

void SessionTable::blockSession(const uint32_t session_hash)
{
    std::unique_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end())
    {
        it->second->isAllowed = false;
    } else
    {
        throw std::runtime_error("Session " + std::to_string(session_hash) + " does not exist!");
    }
}

void SessionTable::printSessionCache()
{
    std::shared_lock lock(_cache_mutex);
    std::cout << std::setw(15) << "State"
              << std::setw(20) << "Destination IP"
              << std::setw(15) << "Ports"
              << std::setw(30) << "Idle Time (sec)" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    const auto current_time = std::chrono::steady_clock::now();

    for (const auto& pair : _session_cache)
    {
        const Session& session = *pair.second;

        std::string state;
        switch (session.current_state) {
            case SYN_SENT:      state = "SYN_SENT"; break;
            case SYN_RECEIVED:  state = "SYN_RECEIVED"; break;
            case ESTABLISHED:   state = "ESTABLISHED"; break;
            case FIN_WAIT1:     state = "FIN_WAIT1"; break;
            case FIN_WAIT2:     state = "FIN_WAIT2"; break;
            case CLOSE_WAIT:    state = "CLOSE_WAIT"; break;
            case TIME_WAIT:     state = "TIME_WAIT"; break;
            case LAST_ACK:      state = "LAST_ACK";  break;
            case UDP:           state = "UDP";  break;
            default:            state = "UNKNOWN"; break;
        }

        // Calculate how many seconds this session has been idle
        const auto idle_duration = std::chrono::duration_cast<std::chrono::seconds>(
            current_time - session.last_active_time
        ).count();

        std::string port_info = std::to_string(session.source_port) + " -> " + std::to_string(session.dst_port);

        std::cout << std::setw(15) << state
                  << std::setw(20) << session.dst_ip.toString()
                  << std::setw(15) << port_info
                  << std::setw(15) << idle_duration << std::endl;
    }
    std::cout << "Total Active sessions: " << _session_cache.size() << std::endl;
}

void SessionTable::sendTableToBackend()
{

    Json::Value active_sessions;
    active_sessions["type"] = "connections update";

    Json::Value tcp_sessions(Json::arrayValue);
    Json::Value udp_sessions(Json::arrayValue);

    std::shared_lock lock(_cache_mutex);

    for (const auto& pair : _session_cache)
    {
        const Session& session = *pair.second;

        if (session.protocol == TCP_PROTOCOL)
        {
            Json::Value tcp_element;
            tcp_element["src_ip"] = session.source_ip.toString();
            tcp_element["dst_ip"] = session.dst_ip.toString();
            tcp_element["src_port"] = std::to_string(session.source_port);
            tcp_element["dst_port"] = std::to_string(session.dst_port);
            switch (session.current_state) {
                case SYN_SENT:      tcp_element["state"] = "SYN_SENT"; break;
                case SYN_RECEIVED:  tcp_element["state"] = "SYN_RECEIVED"; break;
                case ESTABLISHED:   tcp_element["state"] = "ESTABLISHED"; break;
                case FIN_WAIT1:     tcp_element["state"] = "FIN_WAIT1"; break;
                case FIN_WAIT2:     tcp_element["state"] = "FIN_WAIT2"; break;
                case CLOSE_WAIT:    tcp_element["state"] = "CLOSE_WAIT"; break;
                case TIME_WAIT:     tcp_element["state"] = "TIME_WAIT"; break;
                case LAST_ACK:      tcp_element["state"] = "LAST_ACK";  break;
                default:            tcp_element["state"] = "UNKNOWN"; break;
            }
            tcp_sessions.append(tcp_element);
        }
        else
        {
            Json::Value udp_element;
            udp_element["src_ip"] = session.source_ip.toString();
            udp_element["dst_ip"] = session.dst_ip.toString();
            udp_element["src_port"] = std::to_string(session.source_port);
            udp_element["dst_port"] = std::to_string(session.dst_port);
            udp_sessions.append(udp_element);
        }
    }

    active_sessions["tcp"] = tcp_sessions;
    active_sessions["udp"] = udp_sessions;

    // Convert JSON object to string
    const Json::StreamWriterBuilder writer;
    const std::string message = writeString(writer, active_sessions);
    // Send message via WebSocket
    _ws_client.send(message);
}