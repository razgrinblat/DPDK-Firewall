#pragma once
#include <unordered_map>
#include <vector>

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
    std::vector<int> _words_length; //Stores the length of each pattern, used to locate match position in the real text
    int _size; // the size of the trie
    int _root; // ID of the root node (0)
    std::vector<std::string> _patterns; // store actual pattern strings

    /**
     * Calculates the suffix (failure) link for a given node
     * @param vertex the vertex ID
     */
    void calcFailureLink(int vertex);

public:

    AhoCorasick();

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
    int search();

};
