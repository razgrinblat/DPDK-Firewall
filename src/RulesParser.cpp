#include "RulesParser.hpp"

RulesParser::RulesParser(const std::string &file_path) : _file(file_path), _file_path(file_path)
{
    _file.open(file_path);
    if (!_file.is_open()) {
        throw std::runtime_error("Failed to open file: " + _file_path);
    }
}

RulesParser::~RulesParser()
{
    if (_file.is_open()) {
        _file.close();
    }
}

void RulesParser::openAndParseRulesFile()
{
    if (!_file.is_open()) {
        throw std::runtime_error("Failed to open file: " + _file_path);
    }

    Json::Reader reader;
    Json::CharReaderBuilder builder;
    std::string errs;

    _file.clear();  // Clear EOF state or error flags
    _file.seekg(0); // Reset the file pointer to the beginning

    if (!Json::parseFromStream(builder, _file, &_root, &errs)) {
        throw std::runtime_error("Error parsing JSON: " + errs);
    }
}
