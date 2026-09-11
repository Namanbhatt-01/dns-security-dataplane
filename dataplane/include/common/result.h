#pragma once

#include "types.h"
#include <variant>
#include <utility>
#include <stdexcept>

namespace dataplane {

template <typename T>
class Result {
public:
    Result(const T& val) : data_(val) {}
    Result(T&& val) : data_(std::move(val)) {}
    Result(ErrorCode err) : data_(err) {}

    bool is_ok() const { return std::holds_alternative<T>(data_); }
    bool is_err() const { return std::holds_alternative<ErrorCode>(data_); }

    const T& value() const {
        if (is_err()) {
            throw std::runtime_error(std::string("Bad Result access: ") + error_string(error()));
        }
        return std::get<T>(data_);
    }

    T& value() {
        if (is_err()) {
            throw std::runtime_error(std::string("Bad Result access: ") + error_string(error()));
        }
        return std::get<T>(data_);
    }

    ErrorCode error() const {
        if (is_ok()) return ErrorCode::OK;
        return std::get<ErrorCode>(data_);
    }

private:
    std::variant<T, ErrorCode> data_;
};

// Void specialization for operations with no return payload
template <>
class Result<void> {
public:
    Result() : err_(ErrorCode::OK) {}
    Result(ErrorCode err) : err_(err) {}

    bool is_ok() const { return err_ == ErrorCode::OK; }
    bool is_err() const { return err_ != ErrorCode::OK; }
    ErrorCode error() const { return err_; }

private:
    ErrorCode err_;
};

} // namespace dataplane
