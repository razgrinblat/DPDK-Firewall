#pragma once
#include <memory>
#include <Packet.h>
#include <unordered_map>
#include "RulesParser.hpp"

class RuleTree
{

private:
    struct TreeNode
    {
        std::unordered_map<std::string,std::unique_ptr<TreeNode>> children;
        bool action; //True - accept, False - block
    };

    std::unique_ptr<TreeNode> _root;

    RuleTree();
    void buildTree();
    void addRule(const std::unique_ptr<RulesParser::Rule>& rule);


public:
    ~RuleTree() = default;
    RuleTree(const RuleTree&) = delete;
    RuleTree& operator=(const RuleTree&) = delete;
    static RuleTree& getInstance();

    bool allowPacket(const pcpp::Packet& parsed_packet);

};
