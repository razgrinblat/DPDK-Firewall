#pragma once
#include <Packet.h>
#include <unordered_map>
#include "RulesParser.hpp"

class RuleTree
{

private:
    struct TreeNode
    {
        std::unordered_map<std::string,std::shared_ptr<TreeNode>> children;
        std::string action; //True - accept, False - block
    };

    std::shared_ptr<TreeNode> _root;

    RuleTree();
    void addRule(std::unique_ptr<RulesParser::Rule> rule);


public:
    ~RuleTree() = default;
    RuleTree(const RuleTree&) = delete;
    RuleTree& operator=(const RuleTree&) = delete;
    static RuleTree& getInstance();

    void buildTree();
    bool allowPacket(const std::string& protocol, const std::string& ip, const std::string& port);

};
