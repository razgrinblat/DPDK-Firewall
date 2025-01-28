cmake_minimum_required(VERSION 3.10)
project(my_firewall C CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable AddressSanitizer
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")

# Include DPDK headers
include_directories(/usr/local/include/)  # Adjust for DPDK headers
include_directories(/usr/local/include/pcapplusplus)    # PcapPlusPlus headers
include_directories(/usr/local/include/jsoncpp)   #Json header path
include_directories(usr/include/websocketpp)
include_directories(/usr/include/boost) # Boost is required for Websocket
find_package(ZLIB REQUIRED) # Find Zlib on the system
find_package(OpenSSL REQUIRED)

# Link DPDK libraries from /usr/local/lib/x86_64-linux-gnu
link_directories(/usr/local/lib/x86_64-linux-gnu)

# Link PcapPlusPlus libraries
link_directories(/usr/local/lib)
set(PCAPPP_LIBRARIES
        /usr/local/lib/libPcap++.a
        /usr/local/lib/libPacket++.a
        /usr/local/lib/libCommon++.a
)

# Define DPDK libraries
set(DPDK_LIBRARIES
        rte_eal                     # DPDK Environment Abstraction Layer
        rte_mempool                 # DPDK Mempool library
        rte_ring                    # DPDK Ring library
        rte_ethdev                  # DPDK Ethernet device library
        rte_mbuf                    # DPDK Mbuf library
        rte_bus_pci                 # DPDK PCI bus driver
        rte_kvargs                  # DPDK Key-Value arguments library
        rte_pmd_ixgbe               # Example of a specific Poll Mode
)

# System libraries
set(SYSTEM_LIBRARIES
        pcap                        # Required by PcapPlusPlus
        pthread                     # DPDK needs pthread
        m                           # Math library for DPDK
        dl                          # Dynamic linking library for DPDK
        rt                          # Real-time library for DPDK
        numa                        # NUMA support for DPDK
        jsoncpp                     # Jsoncpp library
)

# Boost libraries for Websocket++
set(BOOST_LIBRARIES
        boost_system
        boost_thread
)

# Add the executable
add_executable(my_firewall main.cpp
        PacketSniffer.cpp
        PacketSniffer.hpp
        PacketStats.cpp
        PacketStats.hpp
        QueuesManager.cpp
        QueuesManager.hpp
        RxReceiverThread.cpp
        RxReceiverThread.hpp
        RxSenderThread.cpp
        RxSenderThread.hpp
        TxReceiverThread.cpp
        TxReceiverThread.hpp
        TxSenderThread.cpp
        TxSenderThread.hpp
        Config.hpp
        ArpHandler.cpp
        ArpHandler.hpp
        SessionTable.cpp
        SessionTable.hpp
        TcpSessionHandler.cpp
        TcpSessionHandler.hpp
        IpRulesParser.cpp
        IpRulesParser.hpp
        RuleTree.cpp
        RuleTree.hpp
        InotifyWrapper.cpp
        InotifyWrapper.hpp
        Rule.cpp
        Rule.hpp
        DpiEngine.cpp
        DpiEngine.hpp
        RulesParser.cpp
        RulesParser.hpp
        HttpRulesParser.cpp
        HttpRulesParser.hpp
        HttpRulesHandler.cpp
        HttpRulesHandler.hpp
        WebSocketClient.cpp
        WebSocketClient.hpp
        ClientsManager.cpp
        ClientsManager.hpp
        PortAllocator.cpp
        PortAllocator.hpp
)

# Link DPDK and PcapPlusPlus libraries explicitly
target_link_libraries(my_firewall
        ZLIB::ZLIB
        OpenSSL::SSL
        OpenSSL::Crypto
        ${BOOST_LIBRARIES}
        ${PCAPPP_LIBRARIES}
        ${DPDK_LIBRARIES}
        ${SYSTEM_LIBRARIES}
)