#ifndef LLDBAUTOMATION_H
#define LLDBAUTOMATION_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <condition_variable>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>

#include "api.h"

struct WPInfo
{
    unsigned long long address = 0;
    int bpsize = 0;
    char type;
    bool switch_ = false;
    bool enabled = false;
};

struct CustomDebugEvent
{
    int debugevent;
    int threadid;
    unsigned long long address;
    std::vector<uint64_t> register_;
};

class ThreadSafeQueue
{
private:
    std::queue<std::pair<int, int>> q;
    std::mutex m;
    std::condition_variable cv;

public:
    void put(std::pair<int, int> item)
    {
        std::unique_lock<std::mutex> lock(m);
        q.push(item);
        cv.notify_one();
    }

    std::pair<int, int> get()
    {
        std::unique_lock<std::mutex> lock(m);
        while (q.empty())
        {
            cv.wait(lock);
        }
        auto val = q.front();
        q.pop();
        return val;
    }
};

template <typename T>
T hexStringToNumber(const std::string &hexString, bool is_reverse)
{
    T result;
    std::string HexString;
    if (is_reverse)
    {
        for (std::size_t i = 0; i < hexString.length(); i += 2)
        {
            HexString = hexString.substr(i, 2) + HexString;
        }
    }
    else
    {
        HexString = hexString;
    }

    std::istringstream iss(HexString);
    iss >> std::hex >> result;
    return result;
}

class LLDBAutomation
{
private:
    int s;
    sockaddr_in serv_addr;
    pid_t attach_pid;
    std::string calc_checksum(const std::string &message);
    std::mutex Lock;

public:
    std::vector<CustomDebugEvent> debugevent;
    std::vector<uint64_t> register_info;
    ThreadSafeQueue continue_queue;
    std::vector<WPInfo> wpinfo;
    bool is_stopped;

    LLDBAutomation(const std::string &server_ip, int server_port);
    void disable_ack();
    std::string send_message(const std::string &message, bool recvflag = true);
    void attach(pid_t pid);
    std::string cont();
    std::string cont2(int signal, int thread);
    std::string step(int thread);
    std::string readmem(unsigned long long address, size_t size);
    bool set_watchpoint(unsigned long long address, int size, char _type);
    bool remove_watchpoint(unsigned long long address, int size, char _type);
    std::map<std::string, std::string> parse_result(const std::string &result);
    void interrupt();

    void debugger_thread();
    void interrupt_func();
};

#endif  // LLDBAUTOMATION_H
