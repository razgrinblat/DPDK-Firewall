#include "PortAllocator.hpp"

PortAllocator::PortAllocator() :_generator(_seed()) ,
_free_count(Config::PREALLOCATE_SESSION_TABLE_SIZE)
{
    _pat_table.reserve(Config::PREALLOCATE_SESSION_TABLE_SIZE);

    for (uint16_t i = 0; i < Config::PREALLOCATE_SESSION_TABLE_SIZE; ++i)
    {
        _free_ports_pool[i] = Config::MIN_DYNAMIC_PORT + i;
    }
}

uint16_t PortAllocator::generatePoolIndex()
{
    std::uniform_int_distribution<uint16_t> dist(0, _free_count - 1);
    return dist(_generator);
}

PortAllocator & PortAllocator::getInstance()
{
    static PortAllocator instance;
    return instance;
}

std::optional<std::pair<pcpp::IPv4Address, uint16_t>> PortAllocator::getClientIpAndPort(const uint16_t firewall_port)
{
    std::shared_lock lock(_table_mutex);
    auto it = _pat_table.find(firewall_port);
    if (it != _pat_table.end())
    {
        return it->second;
    }
    return {};
}

uint16_t PortAllocator::allocatePort(const pcpp::IPv4Address& client_ip, const uint16_t client_port)
{
    std::unique_lock lock(_table_mutex);
    const uint16_t pool_index = generatePoolIndex();

    const uint16_t firewall_port = _free_ports_pool[pool_index];
    _free_ports_pool[pool_index] = _free_ports_pool[_free_count - 1];
    _free_count--;

    _pat_table[firewall_port] = {client_ip,client_port};

    return firewall_port;
}

void PortAllocator::releasePort(const uint16_t port)
{
    std::unique_lock lock(_table_mutex);
    if (!_pat_table.erase(port))
    {
        throw std::runtime_error("port: " + std::to_string(port) + " is not found!");
    }
    _free_ports_pool[_free_count++] = port;
}

void PortAllocator::printPortsTable()
{
    std::shared_lock lock(_table_mutex);
    std::cout << std::left << std::setw(15) << "Firewall Port "
              << std::setw(20) << "Client IP"
              << std::setw(15) << "Client Port"
              << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    for (const auto&[firewall_port, ip_port_pair] : _pat_table)
    {
        std::cout << std::left << std::setw(15) << firewall_port << std::setw(20) << ip_port_pair.first.toString()
         << std::setw(15) << ip_port_pair.second << std::endl;
    }
}

void PortAllocator::sendPortsToBackend()
{
    Json::Value pat_table;
    pat_table["type"] = "active ports";
    Json::Value data(Json::arrayValue);

    std::shared_lock lock(_table_mutex);

    for (const auto&[firewall_port, client_ip_port_pair] : _pat_table)
    {
        Json::Value element;
        element["client_ip"] = client_ip_port_pair.first.toString();
        element["client_port"] = client_ip_port_pair.second;
        element["firewall_port"] = firewall_port;

        data.append(element);
    }

    pat_table["data"] = data;

    // Convert JSON object to string
    const Json::StreamWriterBuilder writer;
    const std::string message = writeString(writer, pat_table);
    // Send message via WebSocket
    WebSocketClient::getInstance().send(message);
}
