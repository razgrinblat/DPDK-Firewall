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
    std::cout << "Rules Tree built Successfully" << std::endl;
}

void RuleTree::addRule(const Rule& rule)
{
    std::lock_guard lock_guard(_tree_mutex);
    auto current = _root;
    if(!current->children[rule.protocol])
    {
        current->children[rule.protocol] = std::make_shared<TreeNode>();
    }
    current = current->children[rule.protocol];
    if (!current->children[rule.dst_ip])
    {
        current->children[rule.dst_ip] = std::make_shared<TreeNode>();
    }
    current = current->children[rule.dst_ip];
    const std::string dst_port = std::to_string(rule.dst_port);
    if (!current->children[dst_port])
    {
        current->children[dst_port] = std::make_shared<TreeNode>();
    }
    current = current->children[dst_port];
    current->action = rule.action;
}

void RuleTree::deleteRule(const Rule &rule)
{
    std::lock_guard lock_guard(_tree_mutex);
    auto current = _root;
    if(current->children[rule.protocol])
    {
        std::pair delete_node(_root, rule.protocol);
        current = current->children[rule.protocol];
        if (current->children[rule.dst_ip])
        {
            if (current->children.size() > 1) {
                delete_node = std::make_pair(current,rule.dst_ip);
            }
            current = current->children[rule.dst_ip];
            if (current->children[std::to_string(rule.dst_port)])
            {
                if (current->children.size() > 1) {
                    delete_node = std::make_pair(current,rule.dst_port);
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

void RuleTree::FileEventCallback()
{
    const auto previous_rules = _rules_parser.getCurrentRules();
    _rules_parser.loadRules();
    const auto current_rules = _rules_parser.getCurrentRules();
    for (const auto& rule : current_rules) {
        if( previous_rules.find(rule) == previous_rules.end()) // new Rule added
        {
            std::cout << "Adding new rule" << std::endl;
            addRule(rule);
        }
    }
    for (const auto& rule : previous_rules) {
        if (current_rules.find(rule) == current_rules.end()) // rule was deleted
        {
            std::cout << "Deleting old rule" << std::endl;
            deleteRule(rule);
        }
    }
}

RuleTree & RuleTree::getInstance()
{
    static RuleTree instance;
    return instance;
}

bool RuleTree::allowPacket(const std::string& protocol, const std::string& ip, const std::string& port)
{
    std::lock_guard lock_guard(_tree_mutex);
    auto current = _root;
    if(current->children[protocol])
    {
        current  = current->children[protocol];
        if (current->children[ip])
        {
            current = current->children[ip];
            if (current->children[port])
            {
                current = current->children[port];
                return current->action != "block";
            }
        }
    }
    return true;
}
