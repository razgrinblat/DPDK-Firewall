#include "AhoCorasick.hpp"

void AhoCorasick::calcFailureLink(const int vertex)
{
    // Processing root
    if (vertex == _root)
    {
        _trie[vertex].failure_link = _root;
        return;
    }

    // Processing children of the root
    if (_trie[vertex].parent == _root)
    {
        _trie[vertex].failure_link = _root;
        return;
    }

    // To calculate the failure link for the current vertex, we need the failure
    // link for the parent of the vertex and the character that moved us to the
    // current vertex.

    int next_failure_vertex = _trie[_trie[vertex].parent].failure_link;
    const char char_vertex = _trie[vertex].parent_char;

    while (true)
    {
        // if there is an edge with the needed char in his children,
        // update the failure link to be this child and break
        if (_trie[next_failure_vertex].children.find(char_vertex) != _trie[next_failure_vertex].children.end())
        {
            _trie[vertex].failure_link = _trie[next_failure_vertex].children[char_vertex];
            break;
        }

        // Otherwise, jump by failure links until reach the root or when finding a
        // better prefix for the current substring
        if (next_failure_vertex == _root)
        {
            _trie[vertex].failure_link = _root;
            break;
        }
        next_failure_vertex = _trie[next_failure_vertex].failure_link; // goes up in the trie
    }

    // Inherits all matched pattern outputs from the failure link
    const int failure = _trie[vertex].failure_link;
    _trie[vertex].output_links.insert(
        _trie[vertex].output_links.end(),
        _trie[failure].output_links.begin(),
        _trie[failure].output_links.end());
}

AhoCorasick::AhoCorasick(): _size(0), _root(0), _word_id(0)
{
    // Add root node
    _trie.push_back(Vertex{});
    _size++;
}

void AhoCorasick::clear()
{
    _patterns.clear();
    _trie.clear();
    _trie.push_back(Vertex{}); // Add root node
    _size = 1;      // Only the root node remains
    _word_id = 0;    // Reset word ID counter

}

void AhoCorasick::addString(const std::string &pattern)
{
    _patterns.push_back(pattern);
    int curr_vertex = _root;
    for (const char c : pattern)
    {
        if (_trie[curr_vertex].children.find(c) == _trie[curr_vertex].children.end()) //char doesn't exists, create one
        {
            _trie.push_back(Vertex{});
            _trie[_size].parent = curr_vertex;
            _trie[_size].parent_char = c;
            _trie[curr_vertex].children[c] = _size;
            _size++;
        }
        curr_vertex = _trie[curr_vertex].children[c]; // Move to the new vertex in the trie
    }
    // Mark the end of the word and store its ID
    _trie[curr_vertex].leaf = true;
    _trie[curr_vertex].output_links.push_back(_word_id);
    _word_id++;
}

void AhoCorasick::prepare()
{
    std::queue<int> vertexes_queue; //queue for preforming BFS on the trie
    vertexes_queue.push(_root);

    while (!vertexes_queue.empty())
    {
        const int current_vertex = vertexes_queue.front();
        vertexes_queue.pop();
        calcFailureLink(current_vertex);

        for (const auto& child : _trie[current_vertex].children)
        {
            vertexes_queue.push(child.second);
        }
    }
}

std::optional<std::string> AhoCorasick::search(const std::string& text)
{
    std::unordered_map<std::string, int> match_table;
    int current_node = _root;

    for (int i = 0 ; i < text.size(); ++i)
    {
        // Calculating new node in the trie
        while (true)
        {
            // If we have the edge, then use it
            if (_trie[current_node].children.find(text[i]) != _trie[current_node].children.end())
            {
                current_node = _trie[current_node].children[text[i]];
                break;
            }
            // Otherwise, jump by failure links and try to find the edge with
            // this char
            // If there aren't any possible edges we will eventually ascend to
            // the root, and at this point we stop checking.
            if (current_node == _root) break;

            current_node = _trie[current_node].failure_link;
        }

        // Check for pattern matches at the current node
        for (const int word_id : _trie[current_node].output_links)
        {
            match_table[_patterns[word_id]]++;
        }
    }

    // If no matches found
    if (match_table.empty())
    {
        return {};
    }

    // Collect matches and their counts into a stringstream
    std::stringstream result_stream;
    for (const auto& [pattern, count] : match_table)
    {
        result_stream << "\"" << pattern << "\" found " << count << " times\n";
    }

    // Return the formatted string
    return result_stream.str();
}