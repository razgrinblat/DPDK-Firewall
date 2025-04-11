#pragma once

// This file contains only shared enums and types needed by multiple classes

namespace TCP_COMMON_TYPES
{
    enum TcpState
    {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT1,
        FIN_WAIT2,
        CLOSE_WAIT,
        TIME_WAIT,
        LAST_ACK,
        UNKNOWN,
        UDP
    };

    enum Protocol
    {
        TCP_PROTOCOL,
        UDP_PROTOCOL
    };
}