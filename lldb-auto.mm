#include "lldb-auto.h"

std::string LLDBAutomation::calc_checksum(const std::string &message) {
  int sum = 0;
  for (char c : message) {
    sum += c;
  }
  sum = sum % 256;
  std::stringstream ss;
  ss << std::hex << sum;
  std::string result(ss.str());
  return result.size() == 1 ? "0" + result : result;
}

LLDBAutomation::LLDBAutomation(const std::string &server_ip, int server_port)
    : wpinfo(4) {
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    throw std::runtime_error("Socket creation error");
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(server_port);

  if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0) {
    throw std::runtime_error("Invalid address or Address not supported");
  }

  if (connect(s, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    throw std::runtime_error("Connection Failed");
  }

  send(s, "+", strlen("+"), 0);
  disable_ack();
}

void LLDBAutomation::disable_ack() {
  send(s, "$QStartNoAckMode#b0", strlen("$QStartNoAckMode#b0"), 0);
  char buffer[4096] = {0};
  recv(s, buffer, 4096, 0);
  send(s, "+", strlen("+"), 0);
}

std::string LLDBAutomation::send_message(const std::string &message,
                                         bool recvflag) {
  std::string m = "$" + message + "#" + calc_checksum(message);
  send(s, m.c_str(), m.length(), 0);

  if (recvflag) {
    char buffer[4096] = {0};
    recv(s, buffer, 4096, 0);
    std::string result(buffer);
    return result.substr(1, result.size() - 4);
  }

  return "";
}

void LLDBAutomation::attach(pid_t pid) {
  std::stringstream ss;
  ss << std::hex << pid;
  std::string pid_str(ss.str());
  std::string command = "vAttach;" + pid_str;
  send_message(command);
  attach_pid = pid;
}

std::string LLDBAutomation::cont() { return send_message("c"); }

std::string LLDBAutomation::cont2(int signal, int thread) {
  std::stringstream ss;
  ss << std::hex << signal << ":" << thread;
  std::string command = "vCont;C" + ss.str() + ";c";
  return send_message(command);
}

std::string LLDBAutomation::step(int thread) {
  std::stringstream ss;
  ss << std::hex << thread;
  std::string command = "vCont;s:" + ss.str();
  return send_message(command);
}

std::string LLDBAutomation::readmem(unsigned long long address, size_t size) {
  std::stringstream ss;
  ss << std::hex << address << "," << size;
  std::string command = "x" + ss.str();
  return send_message(command);
}

void LLDBAutomation::interrupt() {
  std::string message = "\x03";
  send_message(message, false);
}

bool LLDBAutomation::set_watchpoint(unsigned long long address, int size,
                                    char _type) {
  std::string command = "";
  if (_type == 'x') {
    command = "Z0";
  } else if (_type == 'w') {
    command = "Z2";
  } else if (_type == 'r') {
    command = "Z3";
  } else if (_type == 'a') {
    command = "Z4";
  }

  std::stringstream ss;
  ss << std::hex << address;

  std::string result =
      send_message(command + "," + ss.str() + "," + std::to_string(size));
  if (result == "OK") {
    return true;
  } else if (result == "E09") {
    return true;
  } else {
    return false;
  }
}

bool LLDBAutomation::remove_watchpoint(unsigned long long address, int size,
                                       char _type) {
  std::string command = "";
  if (_type == 'x') {
    command = "z0";
  } else if (_type == 'w') {
    command = "z2";
  } else if (_type == 'r') {
    command = "z3";
  } else if (_type == 'a') {
    command = "z4";
  }

  std::stringstream ss;
  ss << std::hex << address;

  std::string result =
      send_message(command + "," + ss.str() + "," + std::to_string(size));
  if (result == "OK") {
    return true;
  } else if (result == "E08") {
    return true;
  } else if (result == "") {
    return true;
  } else {
    return false;
  }
}

std::map<std::string, std::string>
LLDBAutomation::parse_result(const std::string &result) {
  std::map<std::string, std::string> _dict;
  std::istringstream iss(result);
  std::string token;

  while (std::getline(iss, token, ';')) {
    size_t pos = token.find(":");
    if (pos != std::string::npos) {
      std::string key = token.substr(0, pos);
      std::string value = token.substr(pos + 1);

      if (key == "medata" && _dict.find(key) != _dict.end()) {
        unsigned int existing_value, new_value;
        std::istringstream(_dict[key]) >> std::hex >> existing_value;
        std::istringstream(value) >> std::hex >> new_value;

        if (new_value > existing_value) {
          _dict[key] = value;
        }
      } else {
        _dict[key] = value;
      }
    }
  }

  return _dict;
}

void LLDBAutomation::debugger_thread() {

  int signal = -1;
  int thread = -1;
  uint64_t address = 0;
  std::string metype;
  std::string result;
  while (true) {
    is_stopped = true;
    std::pair<int, int> c = continue_queue.get();
    is_stopped = false;
    if (c.first == 1) {
      result = cont();
    } else if (c.first == 2) {
      int threadid = c.second;
      result = step(threadid);
    }
    Lock.lock();
    std::map<std::string, std::string> info = parse_result(result);
    if (info.find("metype") == info.end()) {
      printf("Debugger Thread:info is empty.\n");
      Lock.unlock();
      continue;
    }
    metype = info["metype"];

    if (metype == "6") {
      uint64_t medata = hexStringToNumber<uint64_t>(info["medata"], false);
      if (medata == 1) { // Breakpoint
        address = hexStringToNumber<uint64_t>(info["20"], true);
        medata = address;
      } else { // Watchpoint
        medata = hexStringToNumber<uint64_t>(info["medata"], false);
      }
      if (medata > 0x100000) {
        std::string thread_str = "";
        for (const auto &pair : info) {
          if (pair.first.find("thread") != std::string::npos) {
            thread_str = pair.first;
            break;
          }
        }
        int threadid = hexStringToNumber<int>(info[thread_str], false);

        std::vector<uint64_t> register_list;
        for (int i = 0; i < 34; i++) {
          std::stringstream ss;
          ss << std::hex << std::setw(2) << std::setfill('0') << i;

          std::string t = ss.str();
          address = hexStringToNumber<uint64_t>(info[t], true);
          register_list.push_back(address);
        }
        CustomDebugEvent *event = new CustomDebugEvent();
        event->debugevent = 5;
        event->threadid = threadid;
        event->address = medata;
        event->register_ = register_list;
        debugevent.push_back(*event);
      }
    }
    if (metype == "5" || metype == "6") {
      std::string thread_str;
      for (const auto &pair : info) {
        if (pair.first.find("thread") != std::string::npos) {
          thread_str = pair.first;
          break;
        }
      }
      int threadid = hexStringToNumber<int>(info[thread_str], false);
      bool setflag = false;
      // set watchpoint
      for (int i = 0; i < 4; i++) {
        auto wp = wpinfo[i];
        if (wp.switch_ == true && wp.enabled == false) {
          auto address = wp.address;
          auto size = wp.bpsize;
          auto _type = wp.type;
          printf("SetWatchpoint:Address:%llx,Size:%d,Type:%c\n", address, size,
                 _type);
          bool ret = set_watchpoint(address, size, _type);
          printf("Result:%d\n", ret);
          if (ret) {
            wpinfo[i].enabled = true;
          }
          setflag = true;
        }
      }

      // remove watchpoint
      for (int i = 0; i < 4; i++) {
        auto wp = wpinfo[i];
        if (wp.switch_ == false && wp.enabled == true) {
          auto address = wp.address;
          auto size = wp.bpsize;
          auto _type = wp.type;
          printf("RemoveWatchpoint:Address:%llx,Size:%d,Type:%c\n", address,
                 size, _type);
          bool ret = remove_watchpoint(address, size, _type);
          printf("Result:%d\n", ret);
          if (ret) {
            wpinfo[i].enabled = false;
          }
          setflag = true;
        }
      }
      if (setflag) {
        continue_queue.put(std::make_pair(1, threadid));
      }
    }
    Lock.unlock();
  }
}

void LLDBAutomation::interrupt_func() {
  while (true) {
    Lock.lock();
    bool shouldInterrupt = false;

    for (const auto &wp : wpinfo) {
      if ((wp.switch_ && !wp.enabled) || (!wp.switch_ && wp.enabled)) {
        shouldInterrupt = true;
        break;
      }
    }

    if (shouldInterrupt) {
      interrupt();
    }
    Lock.unlock();

    usleep(250000); // 0.25second
  }
}
