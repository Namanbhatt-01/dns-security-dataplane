#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <string_view>
#include <string>

namespace dataplane {

using ByteSpan = std::span<const uint8_t>;
using MutableByteSpan = std::span<uint8_t>;

enum class ErrorCode : uint8_t {
    OK = 0,
    PACKET_TOO_SHORT,
    PACKET_TOO_LARGE,
    INVALID_HEADER,
    INVALID_QDCOUNT,
    INVALID_LABEL_LENGTH,
    POINTER_LOOP_DETECTED,
    POINTER_OUT_OF_BOUNDS,
    INVALID_NAME_TERMINATION,
    NAME_TOO_LONG,
    BUFFER_OVERFLOW,
    UNSUPPORTED_OPCODE,
    MALFORMED_QUESTION,
    UPSTREAM_TIMEOUT,
    UPSTREAM_ERROR,
    UNEXPECTED_RESPONSE
};

inline const char* error_string(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::PACKET_TOO_SHORT: return "Packet too short (<12 bytes)";
        case ErrorCode::PACKET_TOO_LARGE: return "Packet exceeds maximum size";
        case ErrorCode::INVALID_HEADER: return "Invalid DNS header flags";
        case ErrorCode::INVALID_QDCOUNT: return "Invalid QDCOUNT (must be 1)";
        case ErrorCode::INVALID_LABEL_LENGTH: return "Invalid label length (>63 bytes)";
        case ErrorCode::POINTER_LOOP_DETECTED: return "Compression pointer loop cycle detected";
        case ErrorCode::POINTER_OUT_OF_BOUNDS: return "Compression pointer out of packet bounds";
        case ErrorCode::INVALID_NAME_TERMINATION: return "Invalid name null termination";
        case ErrorCode::NAME_TOO_LONG: return "QNAME exceeds 253 characters";
        case ErrorCode::BUFFER_OVERFLOW: return "Output buffer overflow";
        case ErrorCode::UNSUPPORTED_OPCODE: return "Unsupported DNS Opcode";
        case ErrorCode::MALFORMED_QUESTION: return "Question section truncated";
        case ErrorCode::UPSTREAM_TIMEOUT: return "Upstream query timed out";
        case ErrorCode::UPSTREAM_ERROR: return "Upstream returned error";
        case ErrorCode::UNEXPECTED_RESPONSE: return "Upstream response does not match pending query";
        default: return "Unknown error";
    }
}

} // namespace dataplane
