#include "SessionTable.hpp"
#include "DpiEngine.hpp"

SessionTable::SessionTable()
    : _lru_list(Config::PREALLOCATE_SESSION_TABLE_SIZE), _stop_flag(false),
      _port_allocator(PortAllocator::getInstance())
{
    _session_cache.reserve(Config::PREALLOCATE_SESSION_TABLE_SIZE); // Preallocate space to smoother performance
    _clean_up_thread = std::thread(&SessionTable::runCleanUpThread, this);
}

void SessionTable::evictLeastRecentSessionIfNeeded(const uint32_t session_hash, const std::unique_ptr<Session> &session)
{
    uint32_t session_key_to_close;
    if (_lru_list.put(session_hash, &session_key_to_close))
    {
        _session_cache.erase(session_key_to_close);
        _port_allocator.releasePort(session->firewall_port);
    }
}

const std::unique_ptr<SessionTable::Session>&  SessionTable::getSession(const uint32_t session_hash)
{
    const auto it = _session_cache.find(session_hash);
    if (it == _session_cache.end()) throw std::runtime_error("Session does not exist");
    return it->second;
}

void SessionTable::stateMachineProcess(const std::unique_ptr<Session> &session, const pcpp::Packet &packet,
    const pcpp::tcphdr &header, const bool is_outbound)
{
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
        session->state_object = TcpStateFactory::createState(next_state);
    }
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
        std::this_thread::sleep_for(std::chrono::seconds(Config::CLEANUP_IDLE_SESSIONS_TIME)); // avoid busy waiting
    }
}

uint16_t SessionTable::getSessionIdleTimeSeconds(const std::unique_ptr<Session> &session, const std::chrono::steady_clock::time_point& now) const
{
    return static_cast<uint16_t>(
        std::chrono::duration_cast<std::chrono::seconds>(now - session->last_active_time).count()
    );
}

bool SessionTable::shouldRemoveSession(const Session &session, const uint16_t idleTime) const
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

void SessionTable::addNewSession(const uint32_t session_hash, std::unique_ptr<Session> session, const uint32_t packet_size, const TcpState state)
{
    std::unique_lock lock(_cache_mutex);

    evictLeastRecentSessionIfNeeded(session_hash,session);

    session->last_active_time = std::chrono::steady_clock::now();
    if (session->protocol == Protocol::TCP_PROTOCOL) session->state_object = TcpStateFactory::createState(state);
    session->firewall_port = _port_allocator.allocatePort(session->source_ip, session->source_port);
    session->statics.sent_packet_count++;
    session->statics.avg_packet_size = calculateAvgPacketSize(session->statics.avg_packet_size, session->statics.sent_packet_count,
        session->statics.received_packet_count, packet_size);

    _session_cache[session_hash] = std::move(session);
}

void SessionTable::updateSession(const uint32_t session_hash, const uint32_t packet_size, const bool is_outbound, const TcpState new_state)
{
    std::unique_lock lock(_cache_mutex);

    const auto& session = getSession(session_hash);
    if (session->protocol == Protocol::TCP_PROTOCOL) session->state_object = TcpStateFactory::createState(new_state);
    session->last_active_time = std::chrono::steady_clock::now();
    updateStatistics(session, packet_size, is_outbound);
}

void SessionTable::processExistingSession(const uint32_t session_hash, pcpp::Packet &packet, const pcpp::tcphdr &header,
    const bool is_outbound)
{
    std::unique_lock lock(_cache_mutex);

    const auto& session = getSession(session_hash);

    if (session->state_object->getState() == TCP_COMMON_TYPES::ESTABLISHED)
    {
        DpiEngine::getInstance().processDpiTcpPacket(packet,session_hash);
    }

    stateMachineProcess(session, packet, header, is_outbound);

    updateStatistics(session, packet.getRawPacket()->getRawDataLen() , is_outbound);
}

uint16_t SessionTable::getFirewallPort(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    return getSession(session_hash)->firewall_port;
}

std::string & SessionTable::getHttpBuffer(const uint32_t session_hash)
{
    // function called inside FTP Dpi
    return getSession(session_hash)->http_buffer;
}

std::string & SessionTable::getFtpBuffer(const uint32_t session_hash)
{
    // function called inside FTP Dpi
    return getSession(session_hash)->ftp_context.ftp_buffer;
}

bool SessionTable::isAllowed(const uint32_t session_hash)
{
    std::shared_lock lock(_cache_mutex);
    return getSession(session_hash)->isAllowed;
}

bool SessionTable::isFtpDataSession(const uint32_t session_hash)
{
    // function called inside FTP Dpi
    return getSession(session_hash)->ftp_context.ftp_inspection;
}

std::optional<uint32_t> SessionTable::getFtpDataSession(const uint32_t session_hash)
{
    try {
        return getSession(session_hash)->ftp_context.data_channel_session;
    } catch (...) {
        return {};
    }
}

void SessionTable::setFtpDataSession(const uint32_t control_channel_hash, const uint32_t data_channel_hash)
{
    getSession(control_channel_hash)->ftp_context.data_channel_session = data_channel_hash;
}

std::optional<pcpp::FtpRequestLayer::FtpCommand> SessionTable::getFtpRequestCommand(const uint32_t session_hash)
{
    try {
        return getSession(session_hash)->ftp_context.ftp_request_status;
    } catch (...) {
        return {};
    }
}

std::optional<pcpp::FtpResponseLayer::FtpStatusCode> SessionTable::getFtpResponseStatus(const uint32_t session_hash)
{
    try {
        return getSession(session_hash)->ftp_context.ftp_response_status;
    } catch (...) {
        return {};
    }
}

void SessionTable::setFtpRequestCommand(const uint32_t session_hash, pcpp::FtpRequestLayer::FtpCommand command)
{
    getSession(session_hash)->ftp_context.ftp_request_status = command;
}

void SessionTable::setFtpResponseStatus(const uint32_t session_hash, pcpp::FtpResponseLayer::FtpStatusCode status)
{
    getSession(session_hash)->ftp_context.ftp_response_status = status;
}

void SessionTable::blockSession(const uint32_t session_hash)
{
    // function called inside HTTP/FTP Dpi
    getSession(session_hash)->isAllowed = false;
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