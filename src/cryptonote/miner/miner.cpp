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


#include "miner.h"

#include "tools/common/command_line.h"
#include "tools/epee/include/string_tools.h"

#include "math/crypto/controller/random.hpp"

#include "cryptonote/tx/pseudo_functional/tx_utils.hpp"
#include "cryptonote/basic/functional/format_utils.hpp"

#ifdef OpenCL
#include "math/hash/opencl/sha3.hpp"
#endif


#include <execution>


namespace cryptonote
{

  const command_line::arg_descriptor<std::string> arg_start_mining =
    {
      "start-mining"
      , "Specify wallet address to mining for"
      , "", true
    };

  const command_line::arg_descriptor<uint32_t> arg_mining_threads =
    {
      "opencl-mining-threads"
      , "Specify mining threads count"
      , 0
      , true
    };


  miner::miner(i_miner_handler* phandler, const get_block_hash_t &gbh)
    :
    m_stop(true),
    m_template{},
    m_template_no(0),
    m_diffic(0),
    m_phandler(phandler),
    m_gbh(gbh),
    m_height(0),
    m_pauser(false),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_block_reward(0)
  {
  }

  miner::~miner()
  {
    try { stop(); }
    catch (...) { /* ignore */ }
  }

  bool miner::set_block_template
  (
   const block& bl
   , const diff_t& di
   , uint64_t height
   , uint64_t block_reward
   )
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

  bool miner::on_block_chain_update()
  {
    if(!is_mining())
      return true;

    return request_block_template();
  }

  bool miner::request_block_template()
  {
    block bl;
    diff_t di = AUTO_VAL_INIT(di);
    uint64_t height = AUTO_VAL_INIT(height);
    uint64_t expected_reward;
    //only used for RPC calls - could possibly be useful here too?

    cryptonote::string_blob extra_nonce;

    if
      (
       !m_phandler->get_block_template
       (
        bl
        , m_mine_address
        , di
        , height
        , expected_reward
        , extra_nonce
        )
       )
      {
        LOG_ERROR("Failed to get_block_template(), stopping mining");
        return false;
      }

    set_block_template(bl, di, height, expected_reward);
    return true;
  }

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

  void miner::merge_hr()
  {
    if(m_last_hr_merge_time && is_mining())
      {
        m_current_hash_rate =
          m_hashes * 1000 /
          (
           epee::misc_utils::get_tick_count()
           - m_last_hr_merge_time
           + 1
           );
        {
          std::unique_lock<std::mutex> lock(m_last_hash_rates_lock);
          m_last_hash_rates.push_back(m_current_hash_rate);
          if(m_last_hash_rates.size() > 19)
            m_last_hash_rates.pop_front();
        }

        constexpr auto m_do_print_hashrate = false;
        if(m_do_print_hashrate)
          {
            const uint64_t total_hr =
              std::accumulate
              (m_last_hash_rates.begin(), m_last_hash_rates.end(), 0);

            const float hr =
              static_cast<float>(total_hr)
              /
              static_cast<float>(m_last_hash_rates.size());

            const auto flags = std::cout.flags();
            const auto precision = std::cout.precision();
            std::cout
              << "hashrate: "
              << std::setprecision(4)
              << std::fixed
              << hr
              << std::setiosflags(flags)
              << std::setprecision(precision)
              << std::endl;
          }
      }
    m_last_hr_merge_time = epee::misc_utils::get_tick_count();
    m_hashes = 0;
  }

  void miner::init_options
  (boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_start_mining);
    command_line::add_arg(desc, arg_mining_threads);
  }

  bool miner::init
  (
   const boost::program_options::variables_map& vm
   , network_type nettype
   )
  {
    if(command_line::has_arg(vm, arg_start_mining))
      {
        address_parse_info info;
        if
          (
           !cryptonote::get_account_address_from_str
           (
            info, nettype
            , command_line::get_arg(vm, arg_start_mining)
            )
           || info.is_subaddress
           )
          {
            LOG_ERROR
              (
               "Target account address "
               << command_line::get_arg(vm, arg_start_mining)
               << " has wrong format, starting daemon canceled"
               );
            return false;
          }

        m_mine_address = info.address;
        m_threads_total = 1;
        m_do_mining = true;
        if(command_line::has_arg(vm, arg_mining_threads))
          {
            m_threads_total =
              command_line::get_arg(vm, arg_mining_threads);
          }
      }
    return true;
  }

  bool miner::is_mining() const
  {
    return !m_stop;
  }

  const spend_view_public_keys& miner::get_mining_address() const
  {
    return m_mine_address;
  }

  uint32_t miner::get_threads_count() const {
    return m_threads_total;
  }

  bool miner::start
  (const spend_view_public_keys& adr, size_t threads_count)
  {
    m_block_reward = 0;
    m_mine_address = adr;
    m_threads_total =
      std::max(1u, static_cast<uint32_t>(threads_count));

    m_starter_nonce = crypto::rand<uint64_t>();
    std::unique_lock<std::mutex> lock(m_thread_lock);
    if(is_mining())
      {
        LOG_ERROR("Starting miner but it's already started");
        return false;
      }

    if(m_thread)
      {
        LOG_ERROR
          (
           "Unable to start miner because "
           "there are active mining threads"
           );
        return false;
      }

    request_block_template();//lets update block template

    m_stop = false;



#ifdef OpenCL
    const auto maybeGpu = opencl::getGPU();

    if (!maybeGpu) {
      std::cerr << "No OpenCL capable GPUs" << std::endl;
    } else {
      const auto device = *maybeGpu;
      m_thread = {std::thread(&miner::opencl_miner, this, device)};
      return true;
    }
#endif
    m_thread = {std::thread(&miner::worker_thread, this)};
    LOG_INFO("CPU Mining has started with 1 thread");

    return true;
  }

  uint64_t miner::get_speed() const
  {
    if(is_mining()) {
      return m_current_hash_rate;
    }
    else {
      return 0;
    }
  }

  void miner::send_stop_signal()
  {
    m_stop = true;
  }

  bool miner::stop()
  {
    LOG_TRACE("Miner has received stop signal");

    if (!m_thread)
      {
        LOG_TRACE("Not mining - nothing to stop" );
        return true;
      }

    send_stop_signal();

    m_thread->join();

    LOG_INFO("Mining has been stopped");

    m_thread = {};
    return true;
  }

  void miner::on_synchronized()
  {
    if(m_do_mining)
      {
        start(m_mine_address, m_threads_total);
      }
  }

  void miner::pause()
  {
    m_pauser = true;
    LOG_DEBUG("miner::pause");
  }

  void miner::resume()
  {
    m_pauser = false;
    LOG_DEBUG("miner::resume");
  }

  bool miner::worker_thread()
  {
    LOG_GLOBAL_INFO("Miner thread was started");
    uint64_t nonce = m_starter_nonce;
    block b = m_template;
    uint32_t local_template_ver = 0;

    while(!m_stop)
      {
        if(m_pauser)
          {
            epee::misc_utils::sleep_no_w(100);
            continue;
          }

        if(local_template_ver != m_template_no)
        {
          std::unique_lock<std::mutex> lock(m_template_lock);
          local_template_ver = m_template_no;
          b = m_template;
          nonce = m_starter_nonce;
        }

        const diff_t local_diff = m_diffic;

        const boost::multiprecision::uint512_t max_int =
            max_int_for_diff(local_diff);

        const uint64_t height = m_height;

        const epee::blob::data head_full =
            epee::string_tools::string_to_blob
            (get_mining_blob_head(b));

        const epee::blob::data hashing_blob_head
            = head_full.substr
            (0, head_full.length() - sizeof(nonce));

        const epee::blob::data hashing_blob_tail =
            epee::string_tools::string_to_blob
            (cryptonote::get_mining_blob_tail(b));

        if(!local_template_ver)//no any set_block_template call
          {
            LOG_PRINT_L2("Block template not set yet");
            epee::misc_utils::sleep_no_w(1000);
            continue;
          }

        const epee::blob::data nonceData =
          epee::blob::data((const uint8_t*)(&nonce), sizeof(nonce));

        const crypto::hash h = crypto::sha3
          (
           hashing_blob_head
           + nonceData
           + hashing_blob_tail
           );

        const bool valid_hash = hash_to_int(h) <= max_int;

        if(valid_hash && check_hash(h, local_diff))
          {
            block mined_block = b;
            mined_block.nonce = nonce;
            //we lucky!
            LOG_GLOBAL_INFO_GREEN
              (
               "Found block "
               << get_block_hash(mined_block)
               << " at height "
               << height
               << " for difficulty: "
               << local_diff
               );

            cryptonote::block_verification_context bvc;
            if
              (
               !m_phandler->handle_block_found(mined_block, bvc)
               ||
               !bvc.m_added_to_main_chain
               )
              {
              }
          }
        nonce ++;
        m_hashes ++;
      }

    LOG_GLOBAL_INFO("Miner thread stopped");
    return true;
  }

#ifdef OpenCL
  bool miner::opencl_miner(cl::Device device)
  {
    const cl::Context context(device);

    const auto maybeProgram = opencl::getSha3Program(device, context);

    if (!maybeProgram) {
      std::cerr << "Failed to build sha3 OpenCL kernel" << std::endl;
      return false;
    }
    const auto [program, queue] = *maybeProgram;

    LOG_GLOBAL_INFO("OpenCL Miner was started");
    uint64_t nonce = m_starter_nonce;
    uint64_t height = 0;
    uint32_t threads_total = m_threads_total;
    diff_t local_diff = 0;
    uint32_t local_template_ver = 0;
    block b;
    epee::blob::data hashing_blob_head;
    epee::blob::data hashing_blob_tail;
    opencl::cl_mining_template mining_template;
    const size_t gpu_worker_scale = 256;
    const size_t gpu_loop_size = 256;
    const size_t worker_size = threads_total * gpu_worker_scale;

    boost::multiprecision::uint512_t max_int;

    while(!m_stop)
      {
        if(m_pauser)
          {
            epee::misc_utils::sleep_no_w(100);
            continue;
          }

        if(local_template_ver != m_template_no)
          {
            std::unique_lock<std::mutex> lock(m_template_lock);
            b = m_template;
            local_diff = m_diffic;
            max_int = max_int_for_diff(local_diff);
            height = m_height;
            local_template_ver = m_template_no;
            nonce = m_starter_nonce;

            const epee::blob::data head_full =
              epee::string_tools::string_to_blob
              (get_mining_blob_head(b));

            hashing_blob_head =
              head_full.substr(0, head_full.length() - sizeof(nonce));

            hashing_blob_tail = epee::string_tools::string_to_blob
              (cryptonote::get_mining_blob_tail(b));

            std::copy
              (
               hashing_blob_head.begin()
               , hashing_blob_head.end()
               , mining_template.header.begin()
               );

            std::copy
              (
               hashing_blob_tail.begin()
               , hashing_blob_tail.end()
               , mining_template.tail.begin()
               );

            mining_template.tailSize = hashing_blob_tail.size();
            mining_template.hashBound = int_to_hash(max_int).data;
            mining_template.loopSize = gpu_loop_size;
          }

        if(!local_template_ver)//no any set_block_template call
          {
            LOG_PRINT_L2("Block template not set yet");
            epee::misc_utils::sleep_no_w(1000);
            continue;
          }

        using namespace opencl;

        mining_template.nonce = nonce;

        // LOG_GLOBAL_INFO("Mining opencl sha3 on nonce: " << nonce);

        const auto hashes = opencl_sha3
          (
           mining_template
           , worker_size
           , context
           , program
           , queue
           );

        struct hashResult
        {
          bool valid_hash;
          uint64_t nonce;
          crypto::hash hash;
        };

        const hashResult r = std::transform_reduce
          (
           std::execution::par_unseq
           , hashes.begin()
           , hashes.end()
           , hashResult{false, 0}
           , [](const auto& x, const auto& y) {
             if (y.valid_hash) {
               return y;
             }
             return x;
           }
           , [max_int](const auto& x) -> hashResult {
             crypto::hash h;
             h.data = x.hash;
             // const bool is_valid_hash = hash_to_int(h) <= max_int;
             const bool gpu_valid = static_cast<bool>(x.valid);

             return {gpu_valid, x.nonce, h};
           }
           );

        if(r.valid_hash && check_hash(r.hash, local_diff))
          {
            b.nonce = r.nonce;
            //we lucky!
            LOG_GLOBAL_INFO_GREEN
              (
               "Found block "
               << get_block_hash(b)
               << " at height "
               << height
               << " for difficulty: "
               << local_diff
               );

            cryptonote::block_verification_context bvc;
            if
              (
               !m_phandler->handle_block_found(b, bvc)
               ||
               !bvc.m_added_to_main_chain
               )
              {
              }
          }

        nonce += worker_size * gpu_loop_size;
        m_hashes += worker_size * gpu_loop_size;

      }
    LOG_GLOBAL_INFO("OpenCL Miner thread stopped");

    return true;
  }

#endif

}
