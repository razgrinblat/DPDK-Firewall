#include "RuleTree.hpp"

RuleTree::RuleTree() : _root(std::make_shared<TreeNode>()), _rules_parser(RulesParser::getInstance(Config::FILE_PATH))
{
    _file_watcher.addWatch(Config::FILE_PATH, std::bind(&RuleTree::FileEventCallback, this));
    _file_watcher.startWatching();
}

void RuleTree::buildTree()
{
    _rules_parser.loadRules();
     for(const auto& rule : _rules_parser.getCurrentRules())
     {
         addRule(rule);
     }
    std::cout << "Rules Tree built Successfully!" << std::endl;
}

void RuleTree::addRule(const Rule& rule)
{
    std::lock_guard lock_guard(_tree_mutex);
    auto current = _root;
    if(current->children.find(rule.getProtocol()) == current->children.end())
    {
        current->children[rule.getProtocol()] = std::make_shared<TreeNode>();
    }
    current = current->children[rule.getProtocol()];
    if (current->children.find(rule.getDstIp()) == current->children.end())
    {
        current->children[rule.getDstIp()] = std::make_shared<TreeNode>();
    }
    current = current->children[rule.getDstIp()];
    const std::string dst_port = rule.getDstPort();
    if (dst_port == "*" && current->children.size() > 0)
    {
        throw std::invalid_argument("[RULE CONFLICT] Conflicting rules prevent adding rule: " + rule.toString() + ". Delete conflicting rules to proceed.");
    }
    if (current->children.find("*") != current->children.end())
    {
        throw std::invalid_argument("[RULE CONFLICT] General port rule prevents adding rule: " + rule.toString());
    }
    if (current->children.find(dst_port) == current->children.end())
    {
        current->children[dst_port] = std::make_shared<TreeNode>();
    }
    current = current->children[dst_port];
    current->action = rule.getAction();
}

void RuleTree::deleteRule(const Rule &rule)
{
    if (_conflicted_rules.find(rule) == _conflicted_rules.end())
    {
        std::lock_guard lock_guard(_tree_mutex);
        auto current = _root;
        if(current->children.find(rule.getProtocol()) != current->children.end())
        {
            std::pair delete_node(_root, rule.getProtocol());
            current = current->children[rule.getProtocol()];
            if (current->children.find(rule.getDstIp()) != current->children.end())
            {
                if (current->children.size() > 1)
                {
                    delete_node = std::make_pair(current,rule.getDstIp());
                }
                current = current->children[rule.getDstIp()];
                if (current->children.find(rule.getDstPort()) != current->children.end())
                {
                    if (current->children.size() > 1)
                    {
                        delete_node = std::make_pair(current,rule.getDstPort());
                    }
                    delete_node.first->children.erase(delete_node.second);
                }
                else {
                    throw std::runtime_error("Rule to delete not found in the tree!");
                }
            }
            else {
                throw std::runtime_error("Rule to delete not found in the tree!");
            }
        }
        else {
            throw std::runtime_error("Rule to delete not found in the tree!");
        }
    }
    else {
        _conflicted_rules.erase(rule);
    }
}

void RuleTree::resolveConflictedRules(const std::unordered_set<Rule> &current_rules)
{
    for (auto it = _conflicted_rules.begin(); it != _conflicted_rules.end();) // trying to solve and add conflicted rules
    {
        const auto& rule = *it;
        if (current_rules.find(rule) != current_rules.end())
        {
            try {
                addRule(rule);
                std::cout << "Adding new rule -> " << rule << std::endl;
                it = _conflicted_rules.erase(it);
            }
            catch (const std::invalid_argument& e) // there is a rule conflict
            {
                std::cerr << e.what() << std::endl;
                ++it;
            }
        }
        else {
            it = _conflicted_rules.erase(it);
        }
    }
}

void RuleTree::deletingRulesEventHandler(const std::unordered_set<Rule> &previous_rules,
    const std::unordered_set<Rule> &current_rules)
{
    for (const auto& rule : previous_rules)
    {
        if (current_rules.find(rule) == current_rules.end()) // rule was deleted
        {
            deleteRule(rule);
            std::cout << "Deleting old rule -> " << rule << std::endl;
        }
    }
}

void RuleTree::insertingRulesEventHandler(const std::unordered_set<Rule> &previous_rules,
    const std::unordered_set<Rule> &current_rules)
{
    for (const auto& rule : current_rules)
    {
        if(previous_rules.find(rule) == previous_rules.end()) // new Rule added
        {
            try {
                addRule(rule);
                std::cout << "Adding new rule -> " << rule << std::endl;
            }
            catch (const std::invalid_argument& e) // there is a rule conflict
            {
                std::cerr << e.what() << std::endl;
                _conflicted_rules.insert(rule);
            }
        }
    }
}

void RuleTree::FileEventCallback()
{
    // save copy for previous rules copy and load new one - current_rules
    const auto previous_rules = _rules_parser.getCurrentRules();
    try {
        _rules_parser.loadRules();
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
        return;
    }
    const auto current_rules = _rules_parser.getCurrentRules();

    deletingRulesEventHandler(previous_rules, current_rules);
    resolveConflictedRules(current_rules); //trying to resolve and add conflicted rules.
    insertingRulesEventHandler(previous_rules, current_rules);
}

RuleTree & RuleTree::getInstance()
{
    static RuleTree instance;
    return instance;
}

bool RuleTree::isPacketAllowed(const std::string& protocol, const std::string& ip, const std::string& port)
{
    std::lock_guard lock_guard(_tree_mutex);
    auto current = _root;
    if(current->children.find(protocol) != current->children.end())
    {
        current  = current->children[protocol];
        if (current->children.find(ip) != current->children.end())
        {
            current = current->children[ip];
            if (current->children.find(port) != current->children.end())
            {
                current = current->children[port];
                return !(current->action == "block");
            }
            if (current->children.find("*") != current->children.end())
            {
                current = current->children["*"];
                return !(current->action == "block");
            }
        }
    }
    return true;
}

bool RuleTree::handleOutboundForwarding(const pcpp::Packet &parsed_packet)
{
    const pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) {
        return false; // No IPv4 layer, cannot process the packet
    }
    const std::string dst_ip = ipv4_layer->getDstIPv4Address().toString();
    std::string dst_port;

    if (const pcpp::UdpLayer* udp_layer = parsed_packet.getLayerOfType<pcpp::UdpLayer>())
    {
        dst_port = std::to_string(udp_layer->getDstPort());

        // Check if the packet is allowed by the rule tree
        return isPacketAllowed("udp", dst_ip, dst_port);
    }
    if (const pcpp::TcpLayer* tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>())
    {
        dst_port = std::to_string(tcp_layer->getDstPort());

        // Check if the packet is allowed by the rule tree
        return isPacketAllowed("tcp", dst_ip, dst_port);
    }
    return true; // No transport layer found
}

bool RuleTree::handleInboundForwarding(const pcpp::Packet &parsed_packet)
{
    const pcpp::IPv4Layer* ipv4_layer = parsed_packet.getLayerOfType<pcpp::IPv4Layer>();
    if (!ipv4_layer) {
        return false; // No IPv4 layer, cannot process the packet
    }
    const std::string src_ip = ipv4_layer->getSrcIPv4Address().toString();
    std::string src_port;

    if (const pcpp::UdpLayer* udp_layer = parsed_packet.getLayerOfType<pcpp::UdpLayer>())
    {
        src_port = std::to_string(udp_layer->getSrcPort());

        // Check if the packet is allowed by the rule tree
        return isPacketAllowed("udp", src_ip, src_port);
    }
    if (const pcpp::TcpLayer* tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>())
    {
        src_port = std::to_string(tcp_layer->getSrcPort());

        // Check if the packet is allowed by the rule tree
        return isPacketAllowed("tcp", src_ip, src_port);
    }
    return true; // No transport layer found
}
