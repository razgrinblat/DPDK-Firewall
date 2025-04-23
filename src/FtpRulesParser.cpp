#include "FtpRulesParser.hpp"

FtpRulesParser::FtpRulesParser(const std::string &file_path) : RulesParser(file_path){
}

void FtpRulesParser::loadPatternsToAhoCorasick()
{
    _download_ftp_aho_corasick.clear();
    for( const auto& pattern : _ftp_rule_sets.download_key_words)
    {
        _download_ftp_aho_corasick.addString(pattern);
    }
    _download_ftp_aho_corasick.prepare();

    _upload_ftp_aho_corasick.clear();
    for( const auto& pattern : _ftp_rule_sets.upload_key_words)
    {
        _upload_ftp_aho_corasick.addString(pattern);
    }
    _upload_ftp_aho_corasick.prepare();
}

void FtpRulesParser::loadSetFromJson(const Json::Value &json_array, std::unordered_set<std::string> &target_set,
                                      const std::string &field_name)
{
    for (const auto& item : json_array)
    {
        const auto is_inserted = target_set.insert(item.asString());
        if (!is_inserted.second)
        {
            throw std::invalid_argument("Warning! Duplicate value in " + field_name + ": " + item.asString());
        }
    }
}

void FtpRulesParser::loadFtpRules(const Json::Value &ftp_rules)
{
    loadSetFromJson(ftp_rules["download_key_words"], _ftp_rule_sets.download_key_words, "download_key_words");
    loadSetFromJson(ftp_rules["upload_key_words"], _ftp_rule_sets.upload_key_words, "upload_key_words");
    loadSetFromJson(ftp_rules["download_file_names"], _ftp_rule_sets.download_file_names, "download_file_names");
    loadSetFromJson(ftp_rules["upload_file_names"], _ftp_rule_sets.upload_file_names, "upload_file_names");
}


FtpRulesParser & FtpRulesParser::getInstance(const std::string &file_path)
{
    static FtpRulesParser instance(file_path);
    return instance;
}

void FtpRulesParser::loadRules()
{
    _ftp_rule_sets.clear();
    _root.clear();
    static bool already_loaded = false;

    try
    {
        openAndParseRulesFile();
        const Json::Value& ftp_rules = _root["ftp_rules"];
        loadFtpRules(ftp_rules);
        loadPatternsToAhoCorasick();
    }
    catch (const std::exception& e)
    {
        if (already_loaded)
        {
            std::cerr << e.what() << std::endl;
        }
        else
        {
            throw std::invalid_argument(e.what());
        }
    }
    already_loaded = true;
}

const FtpRulesParser::FtpRule & FtpRulesParser::getFtpRules()
{
    return _ftp_rule_sets;
}

AhoCorasick & FtpRulesParser::getUploadFtpAhoCorasick()
{
    return _upload_ftp_aho_corasick;
}

AhoCorasick & FtpRulesParser::getDownloadFtpAhoCorasick()
{
    return _download_ftp_aho_corasick;
}
