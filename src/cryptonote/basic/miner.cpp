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

#include "miner.h"

#include "tools/common/command_line.h"
#include "cryptonote/tx/cryptonote_tx_utils.h"

#include <openssl/evp.h>


#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "miner"


namespace cryptonote
{

  namespace
  {
    const command_line::arg_descriptor<std::string> arg_start_mining = {"start-mining", "Specify wallet address to mining for", "", true};
    const command_line::arg_descriptor<uint32_t> arg_mining_threads =  {"mining-threads", "Specify mining threads count", 0, true};
  }


  miner::miner(i_miner_handler* phandler, const get_block_hash_t &gbh):m_stop(true),
    m_template{},
    m_template_no(0),
    m_diffic(0),
    m_phandler(phandler),
    m_gbh(gbh),
    m_height(0),
    m_threads_active(0),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_block_reward(0)
  {
  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner()
  {
    try { stop(); }
    catch (...) { /* ignore */ }
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const block& bl, const diff_t& di, uint64_t height, uint64_t block_reward)
  {
    std::unique_lock<std::mutex> lock(m_template_lock);
    m_template = bl;
    m_diffic = di;
    m_height = height;
    m_block_reward = block_reward;
    ++m_template_no;
    m_starter_nonce = crypto::rand<uint64_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update()
  {
    if(!is_mining())
      return true;

    return request_block_template();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template()
  {
    block bl;
    diff_t di = AUTO_VAL_INIT(di);
    uint64_t height = AUTO_VAL_INIT(height);
    uint64_t expected_reward; //only used for RPC calls - could possibly be useful here too?

    cryptonote::blobdata extra_nonce;

    if(!m_phandler->get_block_template(bl, m_mine_address, di, height, expected_reward, extra_nonce))
    {
      LOG_ERROR("Failed to get_block_template(), stopping mining");
      return false;
    }
    set_block_template(bl, di, height, expected_reward);
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
    m_update_block_template_interval.do_call([&](){
      if(is_mining())request_block_template();
      return true;
    });

    m_update_merge_hr_interval.do_call([&](){
      merge_hr();
      return true;
    });

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr()
  {
    if(m_last_hr_merge_time && is_mining())
    {
      m_current_hash_rate = m_hashes * 1000 / ((epee::misc_utils::get_tick_count() - m_last_hr_merge_time + 1));
      {
        std::unique_lock<std::mutex> lock(m_last_hash_rates_lock);
        m_last_hash_rates.push_back(m_current_hash_rate);
        if(m_last_hash_rates.size() > 19)
          m_last_hash_rates.pop_front();
      }
      constexpr auto m_do_print_hashrate = false;
      if(m_do_print_hashrate)
      {
        uint64_t total_hr = std::accumulate(m_last_hash_rates.begin(), m_last_hash_rates.end(), 0);
        float hr = static_cast<float>(total_hr)/static_cast<float>(m_last_hash_rates.size());
        const auto flags = std::cout.flags();
        const auto precision = std::cout.precision();
        std::cout << "hashrate: " << std::setprecision(4) << std::fixed << hr << std::setiosflags(flags) << std::setprecision(precision) << std::endl;
      }
    }
    m_last_hr_merge_time = epee::misc_utils::get_tick_count();
    m_hashes = 0;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_start_mining);
    command_line::add_arg(desc, arg_mining_threads);
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::init(const boost::program_options::variables_map& vm, network_type nettype)
  {
    if(command_line::has_arg(vm, arg_start_mining))
    {
      address_parse_info info;
      if(!cryptonote::get_account_address_from_str(info, nettype, command_line::get_arg(vm, arg_start_mining)) || info.is_subaddress)
      {
        LOG_ERROR("Target account address " << command_line::get_arg(vm, arg_start_mining) << " has wrong format, starting daemon canceled");
        return false;
      }
      m_mine_address = info.address;
      m_threads_total = 1;
      m_do_mining = true;
      if(command_line::has_arg(vm, arg_mining_threads))
      {
        m_threads_total = command_line::get_arg(vm, arg_mining_threads);
      }
    }
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining() const
  {
    return !m_stop;
  }
  //-----------------------------------------------------------------------------------------------------
  const account_public_address& miner::get_mining_address() const
  {
    return m_mine_address;
  }
  //-----------------------------------------------------------------------------------------------------
  uint32_t miner::get_threads_count() const {
    return m_threads_total;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::start(const account_public_address& adr, size_t threads_count)
  {
    m_block_reward = 0;
    m_mine_address = adr;
    m_threads_total = std::max(1u, static_cast<uint32_t>(threads_count));

    m_starter_nonce = crypto::rand<uint64_t>();
    std::unique_lock<std::mutex> lock(m_threads_lock);
    if(is_mining())
    {
      LOG_ERROR("Starting miner but it's already started");
      return false;
    }

    if(!m_threads.empty())
    {
      LOG_ERROR("Unable to start miner because there are active mining threads");
      return false;
    }

    request_block_template();//lets update block template

    m_stop = false;

    for(size_t i = 0; i != m_threads_total; i++)
    {
      m_threads.push_back(std::thread(&miner::worker_thread, this, i));
    }

    MINFO("Mining has started with " << threads_count << " threads, good luck!" );

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed() const
  {
    if(is_mining()) {
      return m_current_hash_rate;
    }
    else {
      return 0;
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal()
  {
    m_stop = true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::stop()
  {
    MTRACE("Miner has received stop signal");

    std::unique_lock<std::mutex> lock(m_threads_lock);
    bool mining = !m_threads.empty();
    if (!mining)
    {
      MTRACE("Not mining - nothing to stop" );
      return true;
    }

    send_stop_signal();

    // In case background mining was active and the miner threads are waiting
    // on the background miner to signal start.
    while (m_threads_active > 0)
    {
      epee::misc_utils::sleep_no_w(32);
    }

    MINFO("Mining has been stopped, " << m_threads.size() << " finished" );

    for (auto& thread : m_threads) {
      thread.join();
    }

    m_threads.clear();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
    if(m_do_mining)
    {
      start(m_mine_address, m_threads_total);
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
    std::unique_lock<std::mutex> lock(m_miners_count_lock);
    MDEBUG("miner::pause: " << m_pausers_count << " -> " << (m_pausers_count + 1));
    ++m_pausers_count;
    if(m_pausers_count == 1 && is_mining())
      MDEBUG("MINING PAUSED");
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
    std::unique_lock<std::mutex> lock(m_miners_count_lock);
    MDEBUG("miner::resume: " << m_pausers_count << " -> " << (m_pausers_count - 1));
    --m_pausers_count;
    if(m_pausers_count < 0)
    {
      m_pausers_count = 0;
      MERROR("Unexpected miner::resume() called");
    }
    if(!m_pausers_count && is_mining())
      MDEBUG("MINING RESUMED");
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread(const size_t index)
  {
    uint32_t th_local_index = index;
    MLOG_SET_THREAD_NAME(std::string("[miner ") + std::to_string(th_local_index) + "]");
    MGINFO("Miner thread was started ["<< th_local_index << "]");
    uint64_t nonce = m_starter_nonce + th_local_index;
    uint64_t height = 0;
    uint32_t threads_total = m_threads_total;
    diff_t local_diff = 0;
    uint32_t local_template_ver = 0;
    block b;
    blobdata hashing_blob_head;
    blobdata hashing_blob_tail;
    crypto::hash h = crypto::null_hash;

    uint16_t hashe_count_buffer = 0;
    constexpr uint16_t max16bit = (std::numeric_limits<uint16_t>::max());

    ++m_threads_active;

    boost::multiprecision::uint512_t max_int;

    while(!m_stop.load(std::memory_order_relaxed))
    {
      if(m_pausers_count.load(std::memory_order_relaxed))//anti split workaround
      {
        epee::misc_utils::sleep_no_w(100);
        continue;
      }

      if(local_template_ver != m_template_no.load(std::memory_order_relaxed))
      {
        std::unique_lock<std::mutex> lock(m_template_lock);
        b = m_template;
        local_diff = m_diffic;
        max_int = max_int_for_diff(local_diff);
        height = m_height;
        local_template_ver = m_template_no;
        nonce = m_starter_nonce + th_local_index;
        const blobdata head_full = get_block_hashing_blob_head(b);
        hashing_blob_head = head_full.substr(0, head_full.length() - sizeof(nonce));
        hashing_blob_tail = cryptonote::get_block_hashing_blob_tail(b);
      }

      if(!local_template_ver)//no any set_block_template call
      {
        LOG_PRINT_L2("Block template not set yet");
        epee::misc_utils::sleep_no_w(1000);
        continue;
      }

      EVP_MD_CTX *ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL);
      EVP_DigestUpdate(ctx, hashing_blob_head.data(), hashing_blob_head.length());
      EVP_DigestUpdate(ctx, (const char*)&nonce, sizeof(nonce));
      EVP_DigestUpdate(ctx, hashing_blob_tail.data(), hashing_blob_tail.length());
      EVP_DigestFinal(ctx, (uint8_t*)&h, NULL);
      EVP_MD_CTX_free(ctx);

      const bool valid_hash = hash_to_int(h) <= max_int;

      if(valid_hash && check_hash(h, local_diff))
      {
        b.nonce = nonce;
        //we lucky!
        MGINFO_GREEN("Found block " << get_block_hash(b) << " at height " << height << " for difficulty: " << local_diff);
        cryptonote::block_verification_context bvc;
        if(!m_phandler->handle_block_found(b, bvc) || !bvc.m_added_to_main_chain)
        {
        }
      }
      nonce += threads_total;
      hashe_count_buffer ++;

      if (!hashe_count_buffer) {
        m_hashes += max16bit;
      }
    }
    MGINFO("Miner thread stopped ["<< th_local_index << "]");
    --m_threads_active;
    return true;
  }
}
