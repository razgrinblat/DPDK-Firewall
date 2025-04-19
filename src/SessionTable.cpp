#include "SessionTable.hpp"
#include "DpiEngine.hpp"

SessionTable::SessionTable()
    : _lru_list(Config::MAX_SESSIONS), _stop_flag(false),
      _port_allocator(PortAllocator::getInstance())
{
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread, this);
}

void SessionTable::cleanUpIdleSessions()
{
    const auto current_time = std::chrono::steady_clock::now();

    std::unique_lock lock(_cache_mutex);
    for (auto it = _session_cache.begin(); it != _session_cache.end();)
    {
        const auto& session = it->second;
        const uint16_t idleTime = getSessionIdleTimeSeconds(session, current_time);

        if (shouldRemoveSession(*session, idleTime))
        {
            _port_allocator.releasePort(session->firewall_port);
            _lru_list.eraseElement(it->first);
            it = _session_cache.erase(it);
        }
        else
        {
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

uint16_t SessionTable::getSessionIdleTimeSeconds(const std::unique_ptr<Session> &session, const std::chrono::steady_clock::time_point& now) const
{
    return static_cast<uint16_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - session->last_active_time).count()
    );
}

bool SessionTable::shouldRemoveSession(const Session &session, uint16_t idleTime) const
{
    if (session.protocol == Protocol::UDP_PROTOCOL)
        return idleTime >= Config::MAX_IDLE_SESSION_TIME;

    if (session.protocol == Protocol::TCP_PROTOCOL)
    {

        return idleTime >= Config::MAX_IDLE_SESSION_TIME &&
               (session.state_object->getState() != TcpState::ESTABLISHED || !session.isAllowed);
    }

    return false;
}

void SessionTable::updateStatistics(const std::unique_ptr<Session> &session, const uint32_t size, const bool is_outbound)
{
    session->last_active_time = std::chrono::steady_clock::now();

    if (is_outbound)
        session->statics.sent_packet_count++;
    else
        session->statics.received_packet_count++;

    session->statics.avg_packet_size = calculateAvgPacketSize(
        session->statics.avg_packet_size,
        session->statics.sent_packet_count,
        session->statics.received_packet_count,
        size
    );
}

double SessionTable::calculateAvgPacketSize(const double current_avg, const uint32_t sent, uint32_t recv, uint32_t packet_size)
{
    const uint32_t total = sent + recv;
    return current_avg + (static_cast<double>(packet_size) - current_avg) / total;
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

void SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<Session> session, const TcpState state, const uint32_t packet_size, TcpSessionHandler* tcp_context)
{
    std::unique_lock lock(_cache_mutex);

    uint32_t session_key_to_close;
    if (_lru_list.put(session_hash, &session_key_to_close))
    {
        _session_cache.erase(session_key_to_close);
        _port_allocator.releasePort(session->firewall_port);
    }

    session->last_active_time = std::chrono::steady_clock::now();
    if (tcp_context) session->state_object = TcpStateFactory::createState(state, tcp_context);
    session->firewall_port = _port_allocator.allocatePort(session->source_ip, session->source_port);
    session->statics.sent_packet_count++;
    session->statics.avg_packet_size = calculateAvgPacketSize(session->statics.avg_packet_size, session->statics.sent_packet_count,
        session->statics.received_packet_count, packet_size);
    _session_cache[session_hash] = std::move(session);
}

void SessionTable::updateSession(const uint32_t session_hash, const TcpState new_state, const uint32_t packet_size, const bool is_outbound, TcpSessionHandler* tcp_context)
{
    std::unique_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it == _session_cache.end()) throw std::runtime_error("Session does not exist");

    const auto& session = it->second;;
    if (tcp_context) session->state_object = TcpStateFactory::createState(new_state,tcp_context);
    session->last_active_time = std::chrono::steady_clock::now();
    updateStatistics(session, packet_size, is_outbound);
}

void SessionTable::processStateMachinePacket(const uint32_t hash, pcpp::Packet &packet, const pcpp::tcphdr &header,
                                             const uint32_t packet_size, const bool is_outbound, TcpSessionHandler *context)
{
    std::unique_lock lock(_cache_mutex);

    auto it = _session_cache.find(hash);
    if (it == _session_cache.end()) throw std::runtime_error("Session not found");
    const auto& session = it->second;

    if (session->state_object->getState() == TCP_COMMON_TYPES::ESTABLISHED)
    {
        DpiEngine::getInstance().processDpiTcpPacket(packet, session->ftp_inspection);
    }

    TcpState next_state;
    //state machine process
    if (is_outbound) {
        next_state = session->state_object->handleClientPacket(packet,header);
    }
    else {
        next_state = session->state_object->handleInternetPacket(packet,header);
    }

    if (next_state != session->state_object->getState())
    {
        session->state_object = TcpStateFactory::createState(next_state, context);
    }

    updateStatistics(session, packet_size, is_outbound);
}

uint16_t SessionTable::getFirewallPort(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    auto it = _session_cache.find(session_hash);
    if (it != _session_cache.end()) return it->second->firewall_port;
    throw std::runtime_error("Session not found");
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
        if (session.protocol == Protocol::TCP_PROTOCOL)
        {
            switch (session.state_object->getState()) {
                case TcpState::SYN_SENT:      state = "SYN_SENT"; break;
                case TcpState::SYN_RECEIVED:  state = "SYN_RECEIVED"; break;
                case TcpState::ESTABLISHED:   state = "ESTABLISHED"; break;
                case TcpState::FIN_WAIT1:     state = "FIN_WAIT1"; break;
                case TcpState::FIN_WAIT2:     state = "FIN_WAIT2"; break;
                case TcpState::CLOSE_WAIT:    state = "CLOSE_WAIT"; break;
                case TcpState::TIME_WAIT:     state = "TIME_WAIT"; break;
                case TcpState::LAST_ACK:      state = "LAST_ACK";  break;
                default:            state = "UNKNOWN"; break;
            }
        }
        else state = "UDP";
        // Calculate how many seconds this session has been idle
        const auto idle_duration = std::chrono::duration_cast<std::chrono::seconds>(
            current_time - session.last_active_time
        ).count();

        std::string port_info = std::to_string(session.source_port) + " -> " + std::to_string(session.dst_port);

        std::cout << std::setw(15) << state
                  << std::setw(20) << session.dst_ip.toString()
                  << std::setw(15) << port_info
                  << std::setw(15) << idle_duration
                  << std::setw(15) << session.statics.received_packet_count
                  << std::setw(15) << session.statics.sent_packet_count
                  << std::setw(20) << session.statics.avg_packet_size
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
            switch (session.state_object->getState())
            {
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
            tcp_element["recv_packets"] = std::to_string(session.statics.received_packet_count);
            tcp_element["sent_packets"] = std::to_string(session.statics.sent_packet_count);
            tcp_element["avg_packet_size"] = std::to_string(session.statics.avg_packet_size);

            tcp_sessions.append(tcp_element);
        }
        else
        {
            Json::Value udp_element;
            udp_element["src_ip"] = session.source_ip.toString();
            udp_element["dst_ip"] = session.dst_ip.toString();
            udp_element["src_port"] = std::to_string(session.source_port);
            udp_element["dst_port"] = std::to_string(session.dst_port);
            udp_element["recv_packets"] = std::to_string(session.statics.received_packet_count);
            udp_element["sent_packets"] = std::to_string(session.statics.sent_packet_count);
            udp_element["avg_packet_size"] = std::to_string(session.statics.avg_packet_size);

            udp_sessions.append(udp_element);
        }
    }

    active_sessions["tcp"] = tcp_sessions;
    active_sessions["udp"] = udp_sessions;

    // Convert JSON object to string
    const Json::StreamWriterBuilder writer;
    const std::string message = writeString(writer, active_sessions);
    // Send message via WebSocket
    WebSocketClient::getInstance().send(message);
}