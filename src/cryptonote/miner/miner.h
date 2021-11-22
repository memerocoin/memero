// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include "cryptonote/basic/functional/base.hpp"
#include "cryptonote/basic/type/verification_context.hpp"
#include "math/blockchain/functional/difficulty.hpp"
#include "cryptonote/basic/type/string_blob_type.hpp"

#include "tools/epee/include/math_helper.h"

#include <boost/program_options.hpp>

#ifdef OpenCL

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.hpp>

#endif

namespace cryptonote
{

  struct i_miner_handler
  {
    virtual bool handle_block_found(block& b, block_verification_context &bvc) = 0;
    virtual bool get_block_template(block& b, const spend_view_public_keys& adr, diff_t& diffic, uint64_t& height, uint64_t& expected_reward, const string_blob& ex_nonce) = 0;
  protected:
    ~i_miner_handler(){};
  };

  typedef std::function<bool(const cryptonote::block&, crypto::hash&)> get_block_hash_t;

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class miner
  {
  public:
    miner(i_miner_handler* phandler, const get_block_hash_t& gbh);
    ~miner();
    bool init(const boost::program_options::variables_map& vm, network_type nettype);
    static void init_options(boost::program_options::options_description& desc);
    bool set_block_template(const block& bl, const diff_t& diffic, uint64_t height, uint64_t block_reward);
    bool on_block_chain_update();
    bool start(const spend_view_public_keys& adr, size_t threads_count);
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
    bool worker_thread(const size_t index);

#ifdef OpenCL
    bool opencl_miner
    (
     const cl::Device device
     );
#endif

    bool request_block_template();
    void  merge_hr();

    std::atomic<bool> m_stop;
    std::mutex m_template_lock;
    block m_template;
    std::atomic<uint32_t> m_template_no;
    std::atomic<uint64_t> m_starter_nonce;
    diff_t m_diffic;
    uint64_t m_height;
    std::atomic<uint32_t> m_threads_total;
    std::atomic<uint32_t> m_threads_active;
    std::atomic<int32_t> m_pausers_count;
    std::mutex m_miners_count_lock;

    std::list<std::thread> m_threads;
    std::mutex m_threads_lock;
    i_miner_handler* m_phandler;
    get_block_hash_t m_gbh;
    spend_view_public_keys m_mine_address;
    epee::math_helper::once_a_time_seconds<5> m_update_block_template_interval;
    epee::math_helper::once_a_time_seconds<2> m_update_merge_hr_interval;
    std::atomic<uint64_t> m_last_hr_merge_time;
    std::atomic<uint64_t> m_hashes;
    std::atomic<uint64_t> m_current_hash_rate;
    std::mutex m_last_hash_rates_lock;
    std::list<uint64_t> m_last_hash_rates;
    bool m_do_mining;
    std::atomic<uint64_t> m_block_reward;
  };
}
