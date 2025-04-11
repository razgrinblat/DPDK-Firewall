#include "SessionTable.hpp"

SessionTable::Session::Session(const Protocol protocol, const pcpp::IPv4Address& src_ip, const pcpp::IPv4Address& dst_ip,
                               uint16_t src_port, uint16_t dst_port, TcpState state)
    : isAllowed(true), protocol(protocol), current_state(state), source_ip(src_ip), dst_ip(dst_ip),
      source_port(src_port), dst_port(dst_port), firewall_port(0), received_packet_count(0),
      sent_packet_count(0), avg_packet_size(0.0), state_object(nullptr) {}

SessionTable::SessionTable()
    : _lru_list(Config::MAX_SESSIONS), _stop_flag(false),
      _port_allocator(PortAllocator::getInstance()), _ws_client(WebSocketClient::getInstance())
{
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread, this);
}

SessionTable::~SessionTable()
{
    _stop_flag.store(true);
    if (_clean_up_thread.joinable())
        _clean_up_thread.join();
    _session_cache.clear();
}

SessionTable& SessionTable::getInstance()
{
    static SessionTable instance;
    return instance;
}

bool SessionTable::isSessionExists(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    return _session_cache.find(session_hash) != _session_cache.end();
}

void SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<Session> session, const TcpState state, const uint32_t packet_size, TcpSessionHandler* context)
{
    std::unique_lock lock(_cache_mutex);

    uint32_t session_key_to_close;
    if (_lru_list.put(session_hash, &session_key_to_close))
        _session_cache.erase(session_key_to_close);

    session->last_active_time = std::chrono::steady_clock::now();
    session->current_state = state;
    if (context) session->state_object = TcpStateFactory::createState(state, context);
    session->firewall_port = _port_allocator.allocatePort(session->source_ip, session->source_port);
    session->sent_packet_count++;
    session->avg_packet_size = calculateAvgPacketSize(session->avg_packet_size, session->sent_packet_count, session->received_packet_count, packet_size);
    _session_cache[session_hash] = std::move(session);
}

void SessionTable::updateSession(const uint32_t session_hash, const TcpState new_state, const uint32_t packet_size, const bool is_outbound, TcpSessionHandler* context)
{
    std::unique_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it == _session_cache.end()) throw std::runtime_error("Session does not exist");

    const auto& session = it->second;
    session->current_state = new_state;
    if (context) session->state_object = TcpStateFactory::createState(new_state, context);
    session->last_active_time = std::chrono::steady_clock::now();
    is_outbound ? session->sent_packet_count++ : session->received_packet_count++;
    session->avg_packet_size = calculateAvgPacketSize(session->avg_packet_size, session->sent_packet_count, session->received_packet_count, packet_size);
}

SessionTable::Session* SessionTable::getSession(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) return it->second.get();
    throw std::runtime_error("Session not found");
}

uint16_t SessionTable::getFirewallPort(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) return it->second->firewall_port;
    throw std::runtime_error("Session not found");
}

double SessionTable::calculateAvgPacketSize(const double current_avg, const uint32_t sent, uint32_t recv, uint32_t packet_size)
{
    const uint32_t total = sent + recv;
    return current_avg + (static_cast<double>(packet_size) - current_avg) / total;
}

bool SessionTable::isAllowed(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) return it->second->isAllowed;
    throw std::runtime_error("Session not found");
}

void SessionTable::blockSession(const uint32_t session_hash)
{
    std::unique_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) it->second->isAllowed = false;
    else throw std::runtime_error("Session not found");
}

void SessionTable::printSessionCache()
{
    std::shared_lock lock(_cache_mutex);
    std::cout << std::setw(15) << "State"
              << std::setw(20) << "Destination IP"
              << std::setw(15) << "Ports"
              << std::setw(15) << "Idle Time"
              << std::setw(15) << "Recv Packets"
              << std::setw(15) << "Sent Packets"
              << std::setw(20) << "Avg Packet Size"
              << std::endl;

    std::cout << std::string(115, '-') << std::endl;

    const auto current_time = std::chrono::steady_clock::now();

    for (const auto& pair : _session_cache)
    {
        const Session& session = *pair.second;

        std::string state;
        switch (session.current_state) {
            case TcpState::SYN_SENT:      state = "SYN_SENT"; break;
            case TcpState::SYN_RECEIVED:  state = "SYN_RECEIVED"; break;
            case TcpState::ESTABLISHED:   state = "ESTABLISHED"; break;
            case TcpState::FIN_WAIT1:     state = "FIN_WAIT1"; break;
            case TcpState::FIN_WAIT2:     state = "FIN_WAIT2"; break;
            case TcpState::CLOSE_WAIT:    state = "CLOSE_WAIT"; break;
            case TcpState::TIME_WAIT:     state = "TIME_WAIT"; break;
            case TcpState::LAST_ACK:      state = "LAST_ACK";  break;
            case TcpState::UDP:           state = "UDP";  break;
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
                  << std::setw(15) << idle_duration
                  << std::setw(15) << session.received_packet_count
                  << std::setw(15) << session.sent_packet_count
                  << std::setw(20) << session.avg_packet_size
                  << std::endl;
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

        if (session.protocol == TCP_COMMON_TYPES::TCP_PROTOCOL)
        {
            Json::Value tcp_element;
            tcp_element["src_ip"] = session.source_ip.toString();
            tcp_element["dst_ip"] = session.dst_ip.toString();
            tcp_element["src_port"] = std::to_string(session.source_port);
            tcp_element["dst_port"] = std::to_string(session.dst_port);
            switch (session.current_state) {
                case  TCP_COMMON_TYPES::SYN_SENT:      tcp_element["state"] = "SYN_SENT"; break;
                case TCP_COMMON_TYPES::SYN_RECEIVED:  tcp_element["state"] = "SYN_RECEIVED"; break;
                case TCP_COMMON_TYPES::ESTABLISHED:   tcp_element["state"] = "ESTABLISHED"; break;
                case TCP_COMMON_TYPES::FIN_WAIT1:     tcp_element["state"] = "FIN_WAIT1"; break;
                case TCP_COMMON_TYPES::FIN_WAIT2:     tcp_element["state"] = "FIN_WAIT2"; break;
                case TCP_COMMON_TYPES::CLOSE_WAIT:    tcp_element["state"] = "CLOSE_WAIT"; break;
                case TCP_COMMON_TYPES::TIME_WAIT:     tcp_element["state"] = "TIME_WAIT"; break;
                case TCP_COMMON_TYPES::LAST_ACK:      tcp_element["state"] = "LAST_ACK";  break;
                default:            tcp_element["state"] = "UNKNOWN"; break;
            }
            tcp_element["recv_packets"] = std::to_string(session.received_packet_count);
            tcp_element["sent_packets"] = std::to_string(session.sent_packet_count);
            tcp_element["avg_packet_size"] = std::to_string(session.avg_packet_size);

            tcp_sessions.append(tcp_element);
        }
        else
        {
            Json::Value udp_element;
            udp_element["src_ip"] = session.source_ip.toString();
            udp_element["dst_ip"] = session.dst_ip.toString();
            udp_element["src_port"] = std::to_string(session.source_port);
            udp_element["dst_port"] = std::to_string(session.dst_port);
            udp_element["recv_packets"] = std::to_string(session.received_packet_count);
            udp_element["sent_packets"] = std::to_string(session.sent_packet_count);
            udp_element["avg_packet_size"] = std::to_string(session.avg_packet_size);

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

void SessionTable::cleanUpIdleSessions()
{
    const auto now = std::chrono::steady_clock::now();
    std::unique_lock lock(_cache_mutex);
    for (auto it = _session_cache.begin(); it != _session_cache.end();)
    {
        const auto& session = it->second;
        auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - session->last_active_time).count();
        if (idle >= Config::MAX_IDLE_SESSION_TIME && (session->current_state != TcpState::ESTABLISHED || !session->isAllowed)) {
            _port_allocator.releasePort(session->firewall_port);
            _lru_list.eraseElement(it->first);
            it = _session_cache.erase(it);
        } else {
            ++it;
        }
    }
}

void SessionTable::runCleanUpThread()
{
    while (!_stop_flag.load())
    {
        cleanUpIdleSessions();
        std::this_thread::sleep_for(std::chrono::seconds(Config::CLEANUP_IDLE_SESSIONS_TIME));
    }
}