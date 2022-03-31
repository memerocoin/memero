/*

Copyright 2021 fuwa

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


Parts of this file are originally 
Copyright (c) 2014-2020, The Monero Project

see: etc/other-licenses/monero/LICENSE


Parts of this file are originally 
copyright (c) 2012-2013 The Cryptonote developers

*/

#pragma once

#include "cryptonote/basic/functional/base.hpp"
#include "cryptonote/basic/type/verification_context.hpp"
#include "math/blockchain/functional/difficulty.hpp"
#include "cryptonote/basic/type/string_blob_type.hpp"

#include "tools/epee/include/time_helper.h"

#include <boost/program_options.hpp>

#ifdef OpenCL

#include "math/hash/opencl/cl_version.hpp"

#endif

namespace cryptonote
{

  struct i_miner_handler
  {
    virtual bool handle_block_found
    (block& b, block_verification_context &bvc) = 0;

    virtual bool get_block_template
    (
     block& b
     , const spend_view_public_keys& adr
     , diff_t& diffic
     , uint64_t& expected_reward
     , const string_blob& ex_nonce
     ) = 0;

  protected:
    ~i_miner_handler(){};
  };

  using get_block_hash_t =
  std::function<bool(const cryptonote::block&, crypto::hash&)> ;

  class miner
  {
  public:
    miner(i_miner_handler* phandler, const get_block_hash_t& gbh);
    ~miner();

    bool init
    (
     const boost::program_options::variables_map& vm
     , network_type nettype
     );

    static void init_options
    (boost::program_options::options_description& desc);

    bool set_block_template
    (
     const block& bl
     , const diff_t& diffic
     , uint64_t block_reward
     );

    bool on_block_chain_update();
    bool start
    (const spend_view_public_keys& adr, size_t threads_count);

    uint64_t get_speed() const;
    uint32_t get_threads_count() const;
    void send_stop_signal();
    bool stop();
    bool is_mining() const;
    const spend_view_public_keys& get_mining_address() const;
    bool on_idle();
    void on_synchronized();
    void pause();
    void resume();
    uint64_t get_block_reward() const { return m_block_reward; }

  private:
    bool worker_thread();

#ifdef OpenCL
    bool opencl_miner
    (
     const cl::Device device
     );
#endif

    bool request_block_template();
    void  merge_hr();

    std::atomic<bool> m_stop = true;
    std::mutex m_template_lock;
    std::mutex m_thread_lock;

    block m_template{};
    std::atomic<uint32_t> m_template_no = 0;
    std::atomic<uint64_t> m_starter_nonce = 0;
    diff_t m_diff = 0;
    std::atomic<uint32_t> m_threads_total = 0;
    std::atomic<bool> m_pauser = false;

    std::optional<std::thread> m_thread;

    i_miner_handler* m_phandler;
    get_block_hash_t m_gbh;
    spend_view_public_keys m_mine_address;

    epee::time_helper::once_a_time_seconds<5>
    m_update_block_template_interval;

    epee::time_helper::once_a_time_seconds<2>
    m_update_merge_hr_interval;

    std::atomic<uint64_t> m_last_hr_merge_time = 0;
    std::atomic<uint64_t> m_hashes = 0;
    std::atomic<uint64_t> m_current_hash_rate = 0;
    std::mutex m_last_hash_rates_lock;
    std::list<uint64_t> m_last_hash_rates;
    bool m_do_mining = false;
    std::atomic<uint64_t> m_block_reward = 0;
  };
}
