#include "RuleTree.hpp"

RuleTree::RuleTree()
{

}

void RuleTree::buildTree()
{
    RulesParser& rules_parser = RulesParser::getInstance(Config::FILE_PATH);
    auto rules = rules_parser.getRules();
    for(const auto& rule : rules)
    {
        addRule(std::move(rule));
    }
}

void RuleTree::addRule(const std::unique_ptr<RulesParser::Rule>& rule)
{

}

RuleTree & RuleTree::getInstance()
{

}

bool RuleTree::allowPacket(const pcpp::Packet &parsed_packet)
{

}
