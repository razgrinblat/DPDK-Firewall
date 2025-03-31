#include "WebSocketClient.hpp"

WebSocketClient::WebSocketClient(): _running(false), _is_connected(false)
{
    // Set event handlers
    _client.clear_access_channels(websocketpp::log::alevel::all);
    _client.clear_error_channels(websocketpp::log::elevel::all);

    _client.init_asio();
    _client.set_open_handler(std::bind(&WebSocketClient::onOpen, this, std::placeholders::_1));
    _client.set_close_handler(std::bind(&WebSocketClient::onClose, this, std::placeholders::_1));
    _client.set_fail_handler(std::bind(&WebSocketClient::onFail, this, std::placeholders::_1));
    _client.set_message_handler(std::bind(&WebSocketClient::onMessage, this, std::placeholders::_1, std::placeholders::_2));
}

WebSocketClient::~WebSocketClient()
{
    stop();
}

WebSocketClient & WebSocketClient::getInstance()
{
    static WebSocketClient instance;
    return instance;

}

void WebSocketClient::start(const std::string &uri)
{
    if (_running) return;  // Prevent multiple threads from starting
    _running = true;
    _uri = uri;

    _ws_thread = std::thread(&WebSocketClient::runLoop, this);  // Start main loop in separate thread
}

void WebSocketClient::stop()
{
    _running = false;

    if (_is_connected)
    {
        websocketpp::lib::error_code ec;
        _client.close(_connectionHandle, websocketpp::close::status::going_away, "Client Disconnected", ec);
        if (ec) {
            std::cerr << "Close error: " << ec.message() << std::endl;
        }
    }

    if (_ws_thread.joinable())
    {
        _ws_thread.join();
    }
}

void WebSocketClient::send(const std::string &message)
{
    if (!_is_connected) {
        std::cerr << "[WebSocketClient] Not connected; cannot send." << std::endl;
        return;
    }

    std::error_code error_code;
    {
        std::lock_guard lock(_mutex); // Lock to prevent multiple threads send in the same time
        _client.send(_connectionHandle, message, websocketpp::frame::opcode::text, error_code);
    }

    if (error_code) {
        std::cerr << "Send error: " << error_code.message() << std::endl;
    }
}

void WebSocketClient::setOnMessageCallBack(const std::function<void(const std::string &)> &callback)
{
    _onMessageCallback = callback;
}

void WebSocketClient::runLoop()
{
    while (_running)
    {
        try {
            websocketpp::lib::error_code ec;
            const Client::connection_ptr conn = _client.get_connection(_uri, ec);

            if (ec) {
                std::cerr << "[WebSocketClient] Connection error: " << ec.message() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2)); // Retry delay
                continue;
            }

            _connectionHandle = conn->get_handle();
            _client.connect(conn);

            _client.run();  // Blocks here, runs WebSocket++ event loop
        } catch (const std::exception &e) {
            std::cerr << "[WebSocketClient] Exception: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));  // Wait before retrying
        }
    }
}

void WebSocketClient::onOpen(ConnectionHdl hdl)
{
    _is_connected = true;
    std::cout << "[WebSocketClient] Connected to server." << std::endl;
}

void WebSocketClient::onClose(ConnectionHdl hdl)
{
    _is_connected = false;
    std::cout << "[WebSocketClient] Connection closed." << std::endl;
}

void WebSocketClient::onFail(ConnectionHdl hdl)
{
    _is_connected = false;
    std::cerr << "[WebSocketClient] Connection failed. Retrying..." << std::endl;
    runLoop();
}

void WebSocketClient::onMessage(ConnectionHdl hdl, MessagePtr msg) const
{
    if (_onMessageCallback)
    {
        _onMessageCallback(msg->get_payload());
    }
}
