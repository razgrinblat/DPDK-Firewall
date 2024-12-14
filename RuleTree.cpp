#include "RuleTree.hpp"

RuleTree::RuleTree() : _root(std::make_shared<TreeNode>())
{
}

void RuleTree::buildTree()
{
    RulesParser& rules_parser = RulesParser::getInstance(Config::FILE_PATH);
     for(auto& rule : rules_parser.getRules())
     {
         addRule(std::move(rule));
     }
    std::cout << "Rules Tree built Successfully" << std::endl;
}

void RuleTree::addRule(std::unique_ptr<RulesParser::Rule> rule)
{
    auto current = _root;
    if(!current->children[rule->protocol])
    {
        current->children[rule->protocol] = std::make_shared<TreeNode>();
    }
    current = current->children[rule->protocol];
    if (!current->children[rule->dst_ip])
    {
        current->children[rule->dst_ip] = std::make_shared<TreeNode>();
    }
    current = current->children[rule->dst_ip];
    const std::string dst_port = std::to_string(rule->dst_port);
    if (!current->children[dst_port])
    {
        current->children[dst_port] = std::make_shared<TreeNode>();
    }
    current = current->children[dst_port];
    current->action = rule->action;
}

RuleTree & RuleTree::getInstance()
{
    static RuleTree instance;
    return instance;
}

bool RuleTree::allowPacket(const std::string& protocol, const std::string& ip, const std::string& port)
{
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
