#pragma once
#include <unordered_map>
#include <vector>
#include <queue>
#include <iostream>
#include <sstream>

class AhoCorasick
{
private:

    struct Vertex
    {
        std::unordered_map<char,int> children = {}; // Links to the child vertexes in the trie
        std::vector<int> output_links = {}; // All pattern word IDs ending at this node
        int parent = -1; // Link to the parent vertex
        int failure_link = -1; // failure link from current vertex
        char parent_char; // Char which moves us from the parent vertex to the current vertex
        bool leaf = false; // Flag that some word from the dictionary ends in this vertex
    };

    std::vector<Vertex> _trie; //Holds the entire trie structure as an array of vertexes
    int _size; // the size of the trie
    int _root; // ID of the root node (0)
    std::vector<std::string> _patterns; // store actual pattern strings
    int _word_id; //the last unique ID to each inserted word and is used for tracking matches

    AhoCorasick();
    ~AhoCorasick() = default;

    /**
     * Calculates the suffix (failure) link for a given node
     * @param vertex the vertex ID
     */
    void calcFailureLink(int vertex);

public:

    AhoCorasick(const AhoCorasick&) = delete;
    AhoCorasick& operator=(const AhoCorasick&) = delete;
    static AhoCorasick& getInstance();

    /**
     * clear the trie
     */
    void clear();

    /**
     * Inserts a new pattern string into the trie and assigns it a unique wordID.
     * @param pattern the string to be inserted
     */
    void addString(const std::string& pattern);

    /**
     * Builds failure links and output link logic for efficient pattern matching.
     */
    void prepare();

    /**
     * Processes a given text, searching for all patterns inserted.
     * @return the number of all matched patterns
     */
    std::optional<std::string> search(const std::string& text);
};

// // benchmark example to copy paste in main
// #include "AhoCorasick.hpp"
// #include <chrono>
//
// // --- Naive String Search ---
// int naiveSearch(const std::string &text, const std::vector<std::string> &patterns)
// {
//     int total_matches = 0;
//     for (const std::string &pattern: patterns) {
//         size_t pos = text.find(pattern, 0);
//         while (pos != std::string::npos) {
//             total_matches++;
//             pos = text.find(pattern, pos + 1);
//         }
//     }
//     return total_matches;
// }
//
// // --- Main Benchmark ---
// int main() {
//     std::vector<std::string> patterns;
//     for (int i = 0; i < 200; ++i)
//         patterns.push_back("his" + std::to_string(i));
//
//     std::string text = "she said hello to his friend who was searching for patterns in the world of test cases. ";
//     for (int i = 0; i < 10000; ++i)
//         text += "the new pattern his" + std::to_string(i);
//
//     // Aho-Corasick Benchmark
//     AhoCorasick aho;
//     for (const auto &p: patterns)
//         aho.addString(p);
//     aho.prepare();
//
//     auto start_aho = std::chrono::high_resolution_clock::now();
//     int aho_matches = aho.search(text);
//     auto end_aho = std::chrono::high_resolution_clock::now();
//
//     auto aho_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_aho - start_aho).count();
//     double aho_ms = aho_ns / 1e6;
//
//     std::cout << "[Aho-Corasick] Matches: " << aho_matches
//             << " | Time: " << aho_ns << " ns (" << aho_ms << " ms)\n";
//
//     // Naive Benchmark
//     auto start_naive = std::chrono::high_resolution_clock::now();
//     int naive_matches = naiveSearch(text, patterns);
//     auto end_naive = std::chrono::high_resolution_clock::now();
//
//     auto naive_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_naive - start_naive).count();
//     double naive_ms = naive_ns / 1e6;
//
//     std::cout << "[Naive Search] Matches: " << naive_matches
//             << " | Time: " << naive_ns << " ns (" << naive_ms << " ms)\n";
//
//     return 0;
// }