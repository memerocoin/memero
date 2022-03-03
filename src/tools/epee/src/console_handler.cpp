// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include "tools/epee/include/console_handler.h"

#include <sys/select.h>

namespace epee
{

  // Not thread safe. Only one thread can call this method at once.
  bool async_stdin_reader::get_line(std::string& line)
  {
    if (!start_read())
      return false;

    if (state_eos == m_read_status)
      return false;

    std::unique_lock<std::mutex> lock(m_response_mutex);
    while (state_init == m_read_status)
      {
        m_response_cv.wait(lock);
      }

    bool res = false;
    if (state_success == m_read_status)
      {
        line = m_line;
        res = true;
      }

    if (!eos() && m_read_status != state_cancelled)
      m_read_status = state_init;

    return res;
  }

  void async_stdin_reader::stop()
  {
    if (m_run)
    {
      m_run = false;

      m_request_cv.notify_one();
      m_reader_thread.join();
    }
  }

  void async_stdin_reader::cancel()
  {
    std::unique_lock<std::mutex> lock(m_response_mutex);
    m_read_status = state_cancelled;
    m_has_read_request = false;
    m_response_cv.notify_one();
  }

  bool async_stdin_reader::start_read()
  {
    std::unique_lock<std::mutex> lock(m_request_mutex);
    if (!m_run || m_has_read_request)
      return false;

    m_has_read_request = true;
    m_request_cv.notify_one();
    return true;
  }

  bool async_stdin_reader::wait_read()
  {
    std::unique_lock<std::mutex> lock(m_request_mutex);
    while (m_run && !m_has_read_request)
    {
      m_request_cv.wait(lock);
    }

    if (m_has_read_request)
    {
      m_has_read_request = false;
      return true;
    }

    return false;
  }

  bool async_stdin_reader::wait_stdin_data()
  {
    int stdin_fileno = fileno(stdin);

    while (m_run)
    {
      if (m_read_status == state_cancelled)
        return false;

      fd_set read_set;
      FD_ZERO(&read_set);
      FD_SET(stdin_fileno, &read_set);

      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 100 * 1000;

      int retval = ::select(stdin_fileno + 1, &read_set, NULL, NULL, &tv);
      if (retval < 0)
        return false;
      else if (0 < retval)
        return true;
    }
    return true;
  }

  void async_stdin_reader::reader_thread_func()
  {
    while (true)
    {
      if (!wait_read())
        break;

      std::string line;
      bool read_ok = true;
      if (wait_stdin_data())
      {
        if (m_run)
        {
          if (m_read_status != state_cancelled)
            std::getline(std::cin, line);
          read_ok = !std::cin.eof() && !std::cin.fail();
        }
      }
      else
      {
        read_ok = false;
      }
      if (std::cin.eof()) {
        m_read_status = state_eos;
        m_response_cv.notify_one();
        break;
      }
      else
      {
        std::unique_lock<std::mutex> lock(m_response_mutex);
        if (m_run)
        {
          m_line = std::move(line);
          m_read_status = read_ok ? state_success : state_error;
        }
        else
        {
          m_read_status = state_cancelled;
        }
        m_response_cv.notify_one();
      }
    }
  }

  void async_console_handler::stop()
  {
    m_running = false;
    m_stdin_reader.stop();
  }

  void async_console_handler::cancel()
  {
    m_cancel = true;
    m_stdin_reader.cancel();
  }

  void async_console_handler::print_prompt()
  {
    std::string prompt = m_prompt();
    if (!prompt.empty())
    {
      epee::set_console_color(epee::console_colors::yellow, true);
      std::cout << prompt;
      if (' ' != prompt.back())
        std::cout << ' ';
      epee::reset_console_color();
      std::cout.flush();
    }
  }

  std::string command_handler::get_usage()
  {
    std::stringstream ss;

    for(auto& x:m_command_handlers)
    {
      ss << x.second.second.first << std::endl;
    }
    return ss.str();
  }

  std::pair<std::string, std::string> command_handler::get_documentation(const std::vector<std::string>& cmd)
  {
    if(cmd.empty())
      return std::make_pair("", "");
    auto it = m_command_handlers.find(cmd.front());
    if(it == m_command_handlers.end())
      return std::make_pair("", "");
    return it->second.second;
  }

  void command_handler::set_handler(const std::string& cmd, const callback& hndlr, const std::string& usage, const std::string& description)
  {
    lookup::mapped_type & vt = m_command_handlers[cmd];
    vt.first = hndlr;
    vt.second.first = description.empty() ? cmd : usage;
    vt.second.second = description.empty() ? usage : description;
  }

  void command_handler::set_unknown_command_handler(const callback& hndlr)
  {
    m_unknown_command_handler = hndlr;
  }

  void command_handler::set_empty_command_handler(const empty_callback& hndlr)
  {
    m_empty_command_handler = hndlr;
  }

  void command_handler::set_cancel_handler(const empty_callback& hndlr)
  {
    m_cancel_handler = hndlr;
  }

  bool command_handler::process_command_vec(const std::vector<std::string>& cmd)
  {
    if(!cmd.size() || (cmd.size() == 1 && !cmd[0].size()))
      return m_empty_command_handler();
    auto it = m_command_handlers.find(cmd.front());
    if(it == m_command_handlers.end())
      return m_unknown_command_handler(cmd);
    std::vector<std::string> cmd_local(cmd.begin()+1, cmd.end());
    return it->second.first(cmd_local);
  }

  bool command_handler::process_command_str(const std::optional<std::string>& cmd)
  {
    if (!cmd)
      return m_cancel_handler();
    std::vector<std::string> cmd_v;
    boost::split(cmd_v,*cmd,boost::is_any_of(" "), boost::token_compress_on);
    return process_command_vec(cmd_v);
  }

  bool console_handlers_binder::start_handling(std::function<std::string(void)> prompt, const std::string& usage_string, std::function<void(void)> exit_handler)
  {
    m_console_thread = std::make_unique<std::thread>(&console_handlers_binder::run_handling, this, prompt, usage_string, exit_handler);
    return true;
  }
  bool console_handlers_binder::start_handling(const std::string &prompt, const std::string& usage_string, std::function<void(void)> exit_handler)
  {
    return start_handling([prompt](){ return prompt; }, usage_string, exit_handler);
  }

  void console_handlers_binder::stop_handling()
  {
    m_console_handler.stop();
  }

  bool console_handlers_binder::run_handling(std::function<std::string(void)> prompt, const std::string& usage_string, std::function<void(void)> exit_handler)
  {
    return m_console_handler.run(std::bind(&console_handlers_binder::process_command_str, this, std::placeholders::_1), prompt, usage_string, exit_handler);
  }

  void console_handlers_binder::print_prompt()
  {
    m_console_handler.print_prompt();
  }

  void console_handlers_binder::cancel_input()
  {
    m_console_handler.cancel();
  }

}
