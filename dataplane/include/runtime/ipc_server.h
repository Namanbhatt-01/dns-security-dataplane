#pragma once

#include <string>
#include <thread>
#include <atomic>

namespace dataplane::runtime {

class IpcServer {
public:
    explicit IpcServer(std::string socket_path = "/tmp/dns_dataplane_control.sock");
    ~IpcServer();

    bool start();
    void stop();

private:
    void listen_loop();
    std::string handle_command(const std::string& request_json);

    std::string socket_path_;
    int server_fd_{-1};
    std::atomic<bool> running_{false};
    std::thread worker_thread_;
};

} // namespace dataplane::runtime
