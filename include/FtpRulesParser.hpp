#pragma once
#include "RulesParser.hpp"
#include <unordered_set>
#include "AhoCorasick.hpp"

class FtpRulesParser : public RulesParser
{

public:

    struct FtpRule
    {
        std::unordered_set<std::string> download_key_words;
        std::unordered_set<std::string> upload_key_words;
        std::unordered_set<std::string> download_file_names;
        std::unordered_set<std::string> upload_file_names;

        void clear()
        {
            download_key_words.clear(), upload_key_words.clear(), download_file_names.clear(),
            upload_file_names.clear();
        }
    };

    FtpRulesParser(const FtpRulesParser&) = delete;
    FtpRulesParser& operator=(const FtpRulesParser&) = delete;
    static FtpRulesParser& getInstance(const std::string& file_path);

    void loadRules() override;
    const FtpRule& getFtpRules();

    AhoCorasick& getUploadFtpAhoCorasick();
    AhoCorasick& getDownloadFtpAhoCorasick();

private:

    AhoCorasick _upload_ftp_aho_corasick;
    AhoCorasick _download_ftp_aho_corasick;
    FtpRule _ftp_rule_sets;

    FtpRulesParser(const std::string& file_path);

    void loadPatternsToAhoCorasick();

    void loadSetFromJson(const Json::Value& json_array, std::unordered_set<std::string>& target_set, const std::string& field_name);

    void loadFtpRules(const Json::Value& ftp_rules);


};
