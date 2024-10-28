#pragma once

//NETWORK CONFIGURATION
static constexpr auto MAX_RECEIVE_BURST = 10;
static constexpr auto MBUF_POOL_SIZE = 4095;
static constexpr auto DPDK_DEVICE_1 = 0;
static constexpr auto DPDK_DEVICE_2 = 1;

//THREAD MANAGEMENT
static constexpr auto CORES_TO_USE = 4;

//IP ADDRESSES
static const pcpp::IPv4Address CLIENT_IP("192.168.1.7");
static const pcpp::IPv4Address DPDK_DEVICE2_IP("192.168.1.22"); // "192.168.1.22" or "172.20.10.8" in HOTSPOT
static const pcpp::IPv4Address ROUTER_IP("192.168.1.1"); // 192.168.1.1 or 172.20.10.1 in HOTSPOT

//MAC ADDRESSES
static const pcpp::MacAddress CLIENT_MAC_ADDRESS("08:00:27:42:82:3b");
static const pcpp::MacAddress ROUTER_MAC_ADDRESS("b4:ee:b4:a9:f7:e1"); // "b4:ee:b4:a9:f7:e1" or "fa-87-f1-1a-09-64" in HOTSPOT
static const pcpp::MacAddress BROADCAST_MAC_ADDRESS("ff:ff:ff:ff:ff:ff");
static const pcpp::MacAddress DPDK_DEVICE1_MAC_ADDRESS("08:00:27:b4:8e:4a");
static const pcpp::MacAddress DPDK_DEVICE2_MAC_ADDRESS("08:00:27:9c:49:2f");




