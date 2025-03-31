#include "PortAllocator.hpp"

PortAllocator::PortAllocator() :_generator(_seed()) ,_port_range(Config::MIN_DYNAMIC_PORT,Config::MAX_PORT_NUMBER)
{}

uint16_t PortAllocator::generatePort()
{
    return _port_range(_generator);
}

PortAllocator & PortAllocator::getInstance()
{
    static PortAllocator instance;
    return instance;
}

std::optional<std::pair<pcpp::IPv4Address, uint16_t>> PortAllocator::getClientIpAndPort(const uint16_t firewall_port)
{
    std::shared_lock lock(_table_mutex);
    auto it = _ports_in_use_table.find(firewall_port);
    if (it != _ports_in_use_table.end())
    {
        return it->second;
    }
    return {};
}

uint16_t PortAllocator::allocatePort(const pcpp::IPv4Address& client_ip, const uint16_t client_port)
{
    std::unique_lock lock(_table_mutex);
    uint16_t firewall_port;
    do {
        firewall_port = generatePort();
    }while (_ports_in_use_table.find(firewall_port) != _ports_in_use_table.end()); // port is already in use
    _ports_in_use_table[firewall_port] = {client_ip,client_port};

    return firewall_port;
}

void PortAllocator::releasePort(const uint16_t port)
{
    std::unique_lock lock(_table_mutex);
    if (!_ports_in_use_table.erase(port))
    {
        throw std::runtime_error("port: " + std::to_string(port) + " is not found!");
    }
}

void PortAllocator::printPortsTable()
{
    std::shared_lock lock(_table_mutex);
    std::cout << std::left << std::setw(15) << "Firewall Port "
              << std::setw(20) << "Client IP"
              << std::setw(15) << "Client Port"
              << std::endl;
    std::cout << std::string(50, '-') << std::endl;

    for (const auto&[firewall_port, ip_port_pair] : _ports_in_use_table)
    {
        std::cout << std::left << std::setw(15) << firewall_port << std::setw(20) << ip_port_pair.first.toString()
         << std::setw(15) << ip_port_pair.second << std::endl;
    }
}
