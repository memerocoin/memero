/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

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

// (may contain code and/or modifications by other developers)
// developer rfree: this code is caller of our new network code, and is modded; e.g. for rate limiting


#include "network/p2p/net_node.h"

#include "cryptonote/basic/functional/format_utils.hpp"

#include <boost/uuid/uuid_io.hpp>


#define LOG_P2P_MESSAGE(x)                      \
  LOG_CATEGORY                                  \
  (                                             \
   epee::LogLevel::Verbose, "net.p2p.msg"       \
   , context.to_str()                           \
   + x)

#define LOG_PEER_STATE(x) \
  LOG_INFO \
  ( \
   context.to_str() + "state: " + x + " in state " +  \
   cryptonote::get_protocol_state_string(context.m_state) \
    )

#define BLOCK_QUEUE_NSPANS_THRESHOLD 10 // chunks of N blocks
#define BLOCK_QUEUE_SIZE_THRESHOLD (100*1024*1024) // MB
#define BLOCK_QUEUE_FORCE_DOWNLOAD_NEAR_BLOCKS 1000
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD_STANDBY (5 * 1000000) // microseconds
#define REQUEST_NEXT_SCHEDULED_SPAN_THRESHOLD (30 * 1000000) // microseconds
#define IDLE_PEER_KICK_TIME (240 * 1000000) // microseconds
#define NON_RESPONSIVE_PEER_KICK_TIME (20 * 1000000) // microseconds
#define PASSIVE_PEER_KICK_TIME (60 * 1000000) // microseconds
#define DROP_ON_SYNC_WEDGE_THRESHOLD (30 * 1000000000ull) // nanoseconds
#define LAST_ACTIVITY_STALL_THRESHOLD (2.0f) // seconds
#define DROP_PEERS_ON_SCORE -2

namespace cryptonote
{



  //-----------------------------------------------------------------------------------------------------------------------

  t_cryptonote_protocol_handler::t_cryptonote_protocol_handler(t_core& rcore, nodetool::i_p2p_endpoint<connection_context>* p_net_layout, bool offline)
    :
    m_core(rcore),
    m_p2p(p_net_layout),
    m_synchronized(offline)
  {
    if(!m_p2p)
      m_p2p = &m_p2p_stub;
  }
  //-----------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::init(const boost::program_options::variables_map& vm)
  {
    m_last_add_end_time = 0;
    m_sync_spans_downloaded = 0;
    m_sync_old_spans_downloaded = 0;
    m_sync_bad_spans_downloaded = 0;
    m_sync_download_chain_size = 0;
    m_sync_download_objects_size = 0;

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::deinit()
  {
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::set_p2p_endpoint(nodetool::i_p2p_endpoint<connection_context>* p2p)
  {
    if(p2p)
      m_p2p = p2p;
    else
      m_p2p = &m_p2p_stub;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::on_callback(cryptonote_connection_context& context)
  {
    LOG_PRINT_CCONTEXT_L2("callback fired");
    LOG_ERROR_AND_RETURN_UNLESS
      (
       context.m_callback_request_count > 0
       , false
       , std::string()
       + "["
       + epee::net_utils::print_connection_context_short(context)
       + "]"
       + "false callback fired, but context.m_callback_request_count="
       + std::to_string(context.m_callback_request_count)
       );

    --context.m_callback_request_count;

    if(context.m_state == cryptonote_connection_context::state_synchronizing
       && context.m_last_request_time == std::chrono::time_point<std::chrono::system_clock>::min())
    {
      NOTIFY_REQUEST_CHAIN::request r = {};
      context.m_needed_objects.clear();
      context.m_expect_height = m_core.get_current_blockchain_height();
      m_core.get_short_chain_history(r.block_ids);
      context.m_last_request_time = std::chrono::system_clock::now();
      context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      LOG_P2P_MESSAGE
        (
         "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()="
         + std::to_string(r.block_ids.size())
         );
      post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
      LOG_PEER_STATE("requesting chain");
    }
    else if(context.m_state == cryptonote_connection_context::state_standby)
    {
      context.m_state = cryptonote_connection_context::state_synchronizing;
      try_add_next_blocks(context);
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::log_connections()
  {
    std::stringstream ss;
    ss.precision(1);

    double down_sum = 0.0;
    double down_curr_sum = 0.0;
    double up_sum = 0.0;
    double up_curr_sum = 0.0;

    ss << std::setw(30) << std::left << "Remote Host"
      << std::setw(20) << "Peer id"
      << std::setw(20) << "Support Flags"
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(25) << "State"
      << std::setw(20) << "Livetime(sec)"
      << std::setw(12) << "Down (kB/s)"
      << std::setw(14) << "Down(now)"
      << std::setw(10) << "Up (kB/s)"
      << std::setw(13) << "Up(now)"
      << std::endl;

    m_p2p->for_each_connection([&](const connection_context& cntxt, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      bool local_ip = cntxt.m_remote_address.is_local();
      auto connection_time = time(NULL) - cntxt.m_started;
      ss << std::setw(30) << std::left << std::string(cntxt.m_is_income ? " [INC]":"[OUT]") +
        cntxt.m_remote_address.str()
        << std::setw(20) << nodetool::peerid_to_string(peer_id)
        << std::setw(20) << std::hex << support_flags
        << std::setw(30) << std::to_string(cntxt.m_recv_cnt)+ "(" + std::to_string(time(NULL) - cntxt.m_last_recv) + ")" + "/" + std::to_string(cntxt.m_send_cnt) + "(" + std::to_string(time(NULL) - cntxt.m_last_send) + ")"
        << std::setw(25) << get_protocol_state_string(cntxt.m_state)
        << std::setw(20) << std::to_string(time(NULL) - cntxt.m_started)
        << std::setw(12) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_recv_cnt / connection_time / 1024)
        << std::setw(14) << std::fixed << cntxt.m_current_speed_down / 1024
        << std::setw(10) << std::fixed << (connection_time == 0 ? 0.0 : cntxt.m_send_cnt / connection_time / 1024)
        << std::setw(13) << std::fixed << cntxt.m_current_speed_up / 1024
        << (local_ip ? "[LAN]" : "")
        << std::left << (cntxt.m_remote_address.is_loopback() ? "[LOCALHOST]" : "") // 127.0.0.1
        << std::endl;

      if (connection_time > 1)
      {
        down_sum += (cntxt.m_recv_cnt / connection_time / 1024);
        up_sum += (cntxt.m_send_cnt / connection_time / 1024);
      }

      down_curr_sum += (cntxt.m_current_speed_down / 1024);
      up_curr_sum += (cntxt.m_current_speed_up / 1024);

      return true;
    });
    ss
      << std::endl
      << std::endl
      << std::setw(125) << " "
      << std::setw(12) << down_sum
      << std::setw(14) << down_curr_sum
      << std::setw(10) << up_sum
      << std::setw(13) << up_curr_sum
      << std::endl;
    LOG_PRINT_L0("Connections: " + ss.str());
  }
  //------------------------------------------------------------------------------------------------------------------------
  // Returns a list of connection_info objects describing each open p2p connection
  //------------------------------------------------------------------------------------------------------------------------

  std::list<connection_info> t_cryptonote_protocol_handler::get_connections()
  {
    std::list<connection_info> connections;

    m_p2p->for_each_connection([&](const connection_context& cntxt, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      connection_info cnx;
      auto timestamp = time(NULL);

      cnx.incoming = cntxt.m_is_income ? true : false;

      cnx.address = cntxt.m_remote_address.str();
      cnx.host = cntxt.m_remote_address.host_str();
      cnx.ip = "";
      cnx.port = "";
      if (cntxt.m_remote_address.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id())
      {
        cnx.ip = cnx.host;
        cnx.port = std::to_string(cntxt.m_remote_address.as<epee::net_utils::ipv4_network_address>().port());
      }

      cnx.peer_id = nodetool::peerid_to_string(peer_id);

      cnx.support_flags = support_flags;

      cnx.recv_count = cntxt.m_recv_cnt;
      cnx.recv_idle_time = timestamp - std::max(cntxt.m_started, cntxt.m_last_recv);

      cnx.send_count = cntxt.m_send_cnt;
      cnx.send_idle_time = timestamp - std::max(cntxt.m_started, cntxt.m_last_send);

      cnx.state = get_protocol_state_string(cntxt.m_state);

      cnx.live_time = timestamp - cntxt.m_started;

      cnx.localhost = cntxt.m_remote_address.is_loopback();
      cnx.local_ip = cntxt.m_remote_address.is_local();

      auto connection_time = time(NULL) - cntxt.m_started;
      if (connection_time == 0)
      {
        cnx.avg_download = 0;
        cnx.avg_upload = 0;
      }

      else
      {
        cnx.avg_download = cntxt.m_recv_cnt / connection_time / 1024;
        cnx.avg_upload = cntxt.m_send_cnt / connection_time / 1024;
      }

      cnx.current_download = cntxt.m_current_speed_down / 1024;
      cnx.current_upload = cntxt.m_current_speed_up / 1024;

      cnx.connection_id = epee::string_tools::pod_to_hex(cntxt.m_connection_id);

      cnx.height = cntxt.m_remote_blockchain_height;
      cnx.address_type = (uint8_t)cntxt.m_remote_address.get_type_id();

      connections.push_back(cnx);

      return true;
    });

    return connections;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::process_payload_sync_data(const CORE_SYNC_DATA& hshd, cryptonote_connection_context& context, bool is_inital)
  {
    if(context.m_state == cryptonote_connection_context::state_before_handshake && !is_inital)
      return true;

    if(context.m_state == cryptonote_connection_context::state_synchronizing)
      return true;

    if (hshd.current_height < context.m_remote_blockchain_height)
    {
      LOG_INFO
        (
         context.to_str()
         + "Claims "
         + std::to_string(hshd.current_height)
         + ", claimed "
         + std::to_string(context.m_remote_blockchain_height)
         + " before"
         );
      hit_score(context, 1);
    }
    context.m_remote_blockchain_height = hshd.current_height;

    uint64_t target = m_core.get_target_blockchain_height();
    if (target == 0)
      target = m_core.get_current_blockchain_height();

    if(m_core.have_block(hshd.top_id))
    {
      context.m_state = cryptonote_connection_context::state_normal;
      if(is_inital  && hshd.current_height >= target && target == m_core.get_current_blockchain_height())
        on_connection_synchronized();
      return true;
    }

    if (hshd.current_height > target)
    {
    /* As I don't know if accessing hshd from core could be a good practice,
    I prefer pushing target height to the core at the same time it is pushed to the user.
    Nz. */
    int64_t diff = static_cast<int64_t>(hshd.current_height) - static_cast<int64_t>(m_core.get_current_blockchain_height());
    uint64_t abs_diff = std::abs(diff);
    uint64_t max_block_height = std::max(hshd.current_height,m_core.get_current_blockchain_height());
    uint64_t diff_v2 = std::min(abs_diff, max_block_height);
    LOG_CATEGORY_COLOR
      (
       is_inital ? epee::LogLevel::Info : epee::LogLevel::Debug
       , epee::GLOBAL_CATEGORY
       , epee::console_colors::yellow
       , context.to_str()
       + "Sync data returned a new top block candidate: "
       + std::to_string(m_core.get_current_blockchain_height())
       + " -> "
       + std::to_string(hshd.current_height)
       + " [Your node is "
       + std::to_string(abs_diff)
       + " blocks ("
       + tools::get_human_readable_timespan(diff_v2 * DIFFICULTY_TARGET_IN_SECONDS)
       + ") "
       + (0 <= diff ? std::string("behind") : std::string("ahead"))
       + "]"
       );

    LOG_CATEGORY_COLOR
      (
       is_inital ? epee::LogLevel::Info : epee::LogLevel::Debug
       , epee::GLOBAL_CATEGORY
       , epee::console_colors::yellow
       , "SYNCHRONIZATION started"
       );
      if (hshd.current_height >= m_core.get_current_blockchain_height() + 5) // don't switch to unsafe mode just for a few blocks
      {
        m_core.safesyncmode(false);
      }
      if (m_core.get_target_blockchain_height() == 0) // only when sync starts
      {
        m_last_add_end_time = 0;
        m_sync_spans_downloaded = 0;
        m_sync_old_spans_downloaded = 0;
        m_sync_bad_spans_downloaded = 0;
        m_sync_download_chain_size = 0;
        m_sync_download_objects_size = 0;
      }
    m_core.set_target_blockchain_height((hshd.current_height));
    }
    LOG_INFO
      (
       context.to_str()
       + "Remote blockchain height: "
       + std::to_string(hshd.current_height)
       + ", id: "
       + hshd.top_id.to_str()
       );

    context.m_state = cryptonote_connection_context::state_synchronizing;
    //let the socket to send response to handshake, but request callback, to let send request data after response
    LOG_PRINT_CCONTEXT_L2("requesting callback");
    ++context.m_callback_request_count;
    m_p2p->request_callback(context);
    LOG_PEER_STATE("requesting callback");
    context.m_num_requested = 0;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::get_payload_sync_data(CORE_SYNC_DATA& hshd)
  {
    m_core.get_blockchain_top(hshd.current_height, hshd.top_id);
    diff_t wide_cumulative_difficulty = m_core.get_block_cumulative_difficulty(hshd.current_height);
    hshd.cumulative_difficulty = (wide_cumulative_difficulty & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.cumulative_difficulty_top64 = ((wide_cumulative_difficulty >> 64) & 0xffffffffffffffff).convert_to<uint64_t>();
    hshd.current_height +=1;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

    bool t_cryptonote_protocol_handler::get_payload_sync_data(string_blob& data)
  {
    CORE_SYNC_DATA hsd = {};
    get_payload_sync_data(hsd);
    epee::serialization::store_t_to_binary(hsd, data);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

    int t_cryptonote_protocol_handler::handle_notify_new_block(int command, NOTIFY_NEW_BLOCK::request& arg, cryptonote_connection_context& context)
  {
    const auto r = maybe_block_and_hash_from_blob(arg.b.block);
    if (r) {
      const auto& [block, hash] = *r;
      LOG_P2P_MESSAGE
        (
          "Received NOTIFY_NEW_BLOCK "
          + hash.to_str()
          + " (height "
          + std::to_string(arg.current_blockchain_height)
          + ", "
          + std::to_string(arg.b.txs.size())
          + " txes)"
         );
    }
    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;
    if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
    {
      LOG_DEBUG_CC(context, "Received new block while syncing, ignored");
      return 1;
    }
    m_core.pause_mine();
    std::vector<block_complete_entry> blocks;
    blocks.push_back(arg.b);
    std::vector<block> pblocks;
    if (!m_core.prepare_handle_incoming_blocks(blocks, pblocks))
    {
      LOG_PRINT_CCONTEXT_L1("Block verification failed: prepare_handle_incoming_blocks failed, dropping connection");
      drop_connection(context, false, false);
      m_core.resume_mine();
      return 1;
    }
    for(auto tx_blob_it = arg.b.txs.begin(); tx_blob_it!=arg.b.txs.end();tx_blob_it++)
    {
      cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
      m_core.handle_incoming_ringct(*tx_blob_it, tvc, relay_method::block, true);
      if(tvc.m_verifivation_failed)
      {
        LOG_PRINT_CCONTEXT_L1("Block verification failed: transaction verification failed, dropping connection");
        drop_connection(context, false, false);
        m_core.cleanup_handle_incoming_blocks();
        m_core.resume_mine();
        return 1;
      }
    }

    block_verification_context bvc = {};
    m_core.handle_incoming_block(arg.b.block, pblocks.empty() ? NULL : &pblocks[0], bvc); // got block from handle_notify_new_block
    if (!m_core.cleanup_handle_incoming_blocks(true))
    {
      LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
      m_core.resume_mine();
      return 1;
    }
    m_core.resume_mine();
    if(bvc.m_verifivation_failed)
    {
      LOG_PRINT_CCONTEXT_L0("Block verification failed, dropping connection");
      drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, false);
      return 1;
    }
    if(bvc.m_added_to_main_chain)
    {
      //TODO: Add here announce protocol usage
      relay_block(arg, context);
    }else if(bvc.m_marked_as_orphaned)
    {
      context.m_needed_objects.clear();
      context.m_state = cryptonote_connection_context::state_synchronizing;
      NOTIFY_REQUEST_CHAIN::request r = {};
      context.m_expect_height = m_core.get_current_blockchain_height();
      m_core.get_short_chain_history(r.block_ids);
      context.m_last_request_time = std::chrono::system_clock::now();
      context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      LOG_P2P_MESSAGE
        (
         "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()="
         + std::to_string(r.block_ids.size())
         );
      post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
      LOG_PEER_STATE("requesting chain");
    }

    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_notify_new_fluffy_block(int command, NOTIFY_NEW_FLUFFY_BLOCK::request& arg, cryptonote_connection_context& context)
  {
    const auto r = maybe_block_and_hash_from_blob(arg.b.block);
    if (r) {
      const auto& [block, hash] = *r;
      LOG_P2P_MESSAGE
        (
         "Received NOTIFY_NEW_FLUFFY_BLOCK "
         + hash.to_str()
         + " (height "
         + std::to_string(arg.current_blockchain_height)
         + ", "
         + std::to_string(arg.b.txs.size())
         + " txes)"
         );
    }

    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;
    if(!is_synchronized()) // can happen if a peer connection goes to normal but another thread still hasn't finished adding queued blocks
    {
      LOG_DEBUG_CC(context, "Received new block while syncing, ignored");
      return 1;
    }

    m_core.pause_mine();

    transaction miner_tx;

    const auto maybeBlock = maybe_block_from_blob(arg.b.block);
    if(maybeBlock)
    {
      const block new_block = *maybeBlock;
      // This is a second notification, we must have asked for some missing tx
      if(!context.m_requested_objects.empty())
      {
        // What we asked for != to what we received ..
        if(context.m_requested_objects.size() != arg.b.txs.size())
        {
          LOG_ERROR_CCONTEXT
          (
            "NOTIFY_NEW_FLUFFY_BLOCK -> request/response mismatch, "
            + "block = "
            + epee::string_tools::pod_to_hex(get_blob_hash(arg.b.block))
            + ", requested = "
            + std::to_string(context.m_requested_objects.size())
            + ", received = "
            + std::to_string(new_block.tx_hashes.size())
            + ", dropping connection"
          );

          drop_connection(context, false, false);
          m_core.resume_mine();
          return 1;
        }
      }

      std::vector<tx_blob_entry> have_tx;
      have_tx.reserve(new_block.tx_hashes.size());

      // Instead of requesting missing transactions by hash like BTC,
      // we do it by index (thanks to a suggestion from moneromooo) because
      // we're way cooler .. and also because they're smaller than hashes.
      //
      // Also, remember to pepper some whitespace changes around to bother
      // moneromooo ... only because I <3 him.
      std::vector<uint64_t> need_tx_indices;
      need_tx_indices.reserve(new_block.tx_hashes.size());

      transaction tx;
      crypto::hash tx_hash;

      for(auto& tx_blob: arg.b.txs)
      {
        const auto maybeTx = maybe_tx_from_blob(tx_blob.blob);
        if (maybeTx)
        {
          tx = *maybeTx;
          try
          {
            tx_hash = get_transaction_hash(tx);
          }
          catch(...)
          {
            LOG_PRINT_CCONTEXT_L1
            (
             std::string()
             + "NOTIFY_NEW_FLUFFY_BLOCK: get_transaction_hash failed"
             + ", exception thrown"
             + ", dropping connection"
            );

            drop_connection(context, false, false);
            m_core.resume_mine();
            return 1;
          }

          // hijacking m_requested objects in connection context to patch up
          // a possible DOS vector pointed out by @monero-moo where peers keep
          // sending (0...n-1) transactions.
          // If requested objects is not empty, then we must have asked for
          // some missing transacionts, make sure that they're all there.
          //
          // Can I safely re-use this field? I think so, but someone check me!
          if(!context.m_requested_objects.empty())
          {
            auto req_tx_it = context.m_requested_objects.find(tx_hash);
            if(req_tx_it == context.m_requested_objects.end())
            {
              LOG_ERROR_CCONTEXT
                (
                 std::string()
                 + "Peer sent wrong transaction (NOTIFY_NEW_FLUFFY_BLOCK): "
                 + "transaction with id = "
                 + tx_hash.to_str()
                 + " wasn't requested, "
                 + "dropping connection"
                 );

              drop_connection(context, false, false);
              m_core.resume_mine();
              return 1;
            }

            context.m_requested_objects.erase(req_tx_it);
          }

          // we might already have the tx that the peer
          // sent in our pool, so don't verify again..
          if(!m_core.pool_has_tx(tx_hash))
          {
            LOG_DEBUG
              (
               "Incoming tx "
               + tx_hash.to_str()
               + " not in pool, adding"
               );
            cryptonote::tx_verification_context tvc = AUTO_VAL_INIT(tvc);
            if(!m_core.handle_incoming_ringct(tx_blob, tvc, relay_method::block, true) || tvc.m_verifivation_failed)
            {
              LOG_PRINT_CCONTEXT_L1("Block verification failed: transaction verification failed, dropping connection");
              drop_connection(context, false, false);
              m_core.resume_mine();
              return 1;
            }

            //
            // future todo:
            // tx should only not be added to pool if verification failed, but
            // maybe in the future could not be added for other reasons
            // according to monero-moo so keep track of these separately ..
            //
          }
        }
        else
        {
          LOG_ERROR_CCONTEXT
          (
            "sent wrong tx: failed to parse and validate transaction: "
            + epee::string_tools::buff_to_hex_nodelimer(tx_blob.blob)
            + ", dropping connection"
          );

          drop_connection(context, false, false);
          m_core.resume_mine();
          return 1;
        }
      }

      // The initial size equality check could have been fooled if the sender
      // gave us the number of transactions we asked for, but not the right
      // ones. This check make sure the transactions we asked for were the
      // ones we received.
      if(context.m_requested_objects.size())
      {
        LOG_ERROR
          (
           std::string()
           + "NOTIFY_NEW_FLUFFY_BLOCK: peer sent the number of transaction requested"
           + ", but not the actual transactions requested"
           + ", context.m_requested_objects.size() = "
           + std::to_string(context.m_requested_objects.size())
           + ", dropping connection"
           );

        drop_connection(context, false, false);
        m_core.resume_mine();
        return 1;
      }

      size_t tx_idx = 0;
      for(auto& tx_hash: new_block.tx_hashes)
      {
        cryptonote::string_blob txblob;
        if(m_core.get_pool_transaction(tx_hash, txblob, relay_category::broadcasted))
        {
          have_tx.push_back({txblob, crypto::null_hash});
        }
        else
        {
          std::vector<crypto::hash> tx_ids;
          std::vector<transaction> txes;
          std::vector<crypto::hash> missing;
          tx_ids.push_back(tx_hash);
          if (m_core.get_transactions(tx_ids, txes, missing) && missing.empty())
          {
            if (txes.size() == 1)
            {
              have_tx.push_back({tx_to_blob(txes.front()), crypto::null_hash});
            }
            else
            {
              LOG_ERROR
                (
                 "1 tx requested, none not found, but "
                 + std::to_string(txes.size())
                 + " returned"
                 );
              m_core.resume_mine();
              return 1;
            }
          }
          else
          {
            LOG_DEBUG("Tx " + tx_hash.to_str() + " not found in pool");
            need_tx_indices.push_back(tx_idx);
          }
        }

        ++tx_idx;
      }

      if(!need_tx_indices.empty()) // drats, we don't have everything..
      {
        // request non-mempool txs
        LOG_DEBUG
          (
           "We are missing "
           + std::to_string(need_tx_indices.size())
           + " txes for this fluffy block"
           );
        for (auto txidx: need_tx_indices) {
          LOG_DEBUG("  tx " + new_block.tx_hashes[txidx].to_str());
        }
        NOTIFY_REQUEST_FLUFFY_MISSING_TX::request missing_tx_req;
        missing_tx_req.block_hash = get_block_hash(new_block);
        missing_tx_req.current_blockchain_height = arg.current_blockchain_height;
        missing_tx_req.missing_tx_indices = std::move(need_tx_indices);

        m_core.resume_mine();
        LOG_P2P_MESSAGE
          (
           "-->>NOTIFY_REQUEST_FLUFFY_MISSING_TX: missing_tx_indices.size()="
           + std::to_string(missing_tx_req.missing_tx_indices.size())
           );
        post_notify<NOTIFY_REQUEST_FLUFFY_MISSING_TX>(missing_tx_req, context);
      }
      else // whoo-hoo we've got em all ..
      {
        LOG_DEBUG("We have all needed txes for this fluffy block");

        block_complete_entry b;
        b.block = arg.b.block;
        b.txs = have_tx;

        std::vector<block_complete_entry> blocks;
        blocks.push_back(b);
        std::vector<block> pblocks;
        if (!m_core.prepare_handle_incoming_blocks(blocks, pblocks))
        {
          LOG_PRINT_CCONTEXT_L0("Failure in prepare_handle_incoming_blocks");
          m_core.resume_mine();
          return 1;
        }

        block_verification_context bvc = {};
        m_core.handle_incoming_block(arg.b.block, pblocks.empty() ? NULL : &pblocks[0], bvc); // got block from handle_notify_new_block
        if (!m_core.cleanup_handle_incoming_blocks(true))
        {
          LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
          m_core.resume_mine();
          return 1;
        }
        m_core.resume_mine();

        if( bvc.m_verifivation_failed )
        {
          LOG_PRINT_CCONTEXT_L0("Block verification failed, dropping connection");
          drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, false);
          return 1;
        }
        if( bvc.m_added_to_main_chain )
        {
          //TODO: Add here announce protocol usage
          NOTIFY_NEW_BLOCK::request reg_arg = AUTO_VAL_INIT(reg_arg);
          reg_arg.current_blockchain_height = arg.current_blockchain_height;
          reg_arg.b = b;
          relay_block(reg_arg, context);
        }
        else if( bvc.m_marked_as_orphaned )
        {
          context.m_needed_objects.clear();
          context.m_state = cryptonote_connection_context::state_synchronizing;
          NOTIFY_REQUEST_CHAIN::request r = {};
          context.m_expect_height = m_core.get_current_blockchain_height();
          m_core.get_short_chain_history(r.block_ids);
          context.m_last_request_time = std::chrono::system_clock::now();
          context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
          LOG_P2P_MESSAGE
            (
             "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()="
             + std::to_string(r.block_ids.size())
             );
          post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
          LOG_PEER_STATE("requesting chain");
        }
      }
    }
    else
    {
      LOG_ERROR_CCONTEXT
      (
        "sent wrong block: failed to parse and validate block: "
        + epee::string_tools::buff_to_hex_nodelimer(arg.b.block)
        + ", dropping connection"
      );

      m_core.resume_mine();
      drop_connection(context, false, false);

      return 1;
    }

    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_request_fluffy_missing_tx(int command, NOTIFY_REQUEST_FLUFFY_MISSING_TX::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_REQUEST_FLUFFY_MISSING_TX ("
       + std::to_string(arg.missing_tx_indices.size())
       + " txes), block hash "
       + arg.block_hash.to_str()
       );
    if (context.m_state == cryptonote_connection_context::state_before_handshake)
    {
      LOG_ERROR_CCONTEXT("Requested fluffy tx before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    std::vector<std::pair<cryptonote::string_blob, block>> local_blocks;
    std::vector<cryptonote::string_blob> local_txs;

    block b;
    if (!m_core.get_block_by_hash(arg.block_hash, b))
    {
      LOG_ERROR_CCONTEXT
        (
         "failed to find block: "
         + arg.block_hash.to_str()
         + ", dropping connection"
         );
      drop_connection(context, false, false);
      return 1;
    }

    std::vector<crypto::hash> txids;
    txids.reserve(b.tx_hashes.size());
    NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_response;
    fluffy_response.b.block = t_serializable_object_to_blob(b);
    fluffy_response.current_blockchain_height = arg.current_blockchain_height;
    std::vector<bool> seen(b.tx_hashes.size(), false);
    for(auto& tx_idx: arg.missing_tx_indices)
    {
      if(tx_idx < b.tx_hashes.size())
      {
        LOG_DEBUG("  tx " + b.tx_hashes[tx_idx].to_str());
        if (seen[tx_idx])
        {
          LOG_ERROR_CCONTEXT
          (
            "Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX"
            + ", request is asking for duplicate tx "
            + ", tx index = "
            + std::to_string(tx_idx)
            + ", block tx count "
            + std::to_string(b.tx_hashes.size())
            + ", block_height = "
            + std::to_string(arg.current_blockchain_height)
            + ", dropping connection"
          );
          drop_connection(context, true, false);
          return 1;
        }
        txids.push_back(b.tx_hashes[tx_idx]);
        seen[tx_idx] = true;
      }
      else
      {
        LOG_ERROR_CCONTEXT
          (
           "Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX"
           + ", request is asking for a tx whose index is out of bounds "
           + ", tx index = "
           + std::to_string(tx_idx)
           + ", block tx count "
           + std::to_string(b.tx_hashes.size())
           + ", block_height = "
           + std::to_string(arg.current_blockchain_height)
           + ", dropping connection"
           );

        drop_connection(context, false, false);
        return 1;
      }
    }

    std::vector<cryptonote::transaction> txs;
    std::vector<crypto::hash> missed;
    if (!m_core.get_transactions(txids, txs, missed))
    {
      LOG_ERROR_CCONTEXT("Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX, "
        + "failed to get requested transactions");
      drop_connection(context, false, false);
      return 1;
    }
    if (!missed.empty() || txs.size() != txids.size())
    {
      LOG_ERROR_CCONTEXT
        (
         "Failed to handle request NOTIFY_REQUEST_FLUFFY_MISSING_TX, "
         + std::to_string(missed.size())
         + " requested transactions not found"
         + ", dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    for(auto& tx: txs)
    {
      fluffy_response.b.txs.push_back({t_serializable_object_to_blob(tx), crypto::null_hash});
    }

    LOG_P2P_MESSAGE
      (
       "-->>NOTIFY_RESPONSE_FLUFFY_MISSING_TX: "
       + ", txs.size()="
       + std::to_string(fluffy_response.b.txs.size())
       + ", rsp.current_blockchain_height="
       + std::to_string(fluffy_response.current_blockchain_height)
       );

    post_notify<NOTIFY_NEW_FLUFFY_BLOCK>(fluffy_response, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_notify_get_txpool_complement(int command, NOTIFY_GET_TXPOOL_COMPLEMENT::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_GET_TXPOOL_COMPLEMENT ("
       + std::to_string(arg.hashes.size())
       + " txes)"
       );
    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;

    std::vector<std::pair<cryptonote::string_blob, block>> local_blocks;
    std::vector<cryptonote::string_blob> local_txs;

    std::vector<cryptonote::string_blob> txes;
    if (!m_core.get_txpool_complement(arg.hashes, txes))
    {
      LOG_ERROR_CCONTEXT("failed to get txpool complement");
      return 1;
    }

    NOTIFY_NEW_TRANSACTIONS::request new_txes;
    new_txes.txs = std::move(txes);

    LOG_P2P_MESSAGE
      (
       "-->>NOTIFY_NEW_TRANSACTIONS: "
       + ", txs.size()="
       + std::to_string(new_txes.txs.size())
       );

    post_notify<NOTIFY_NEW_TRANSACTIONS>(new_txes, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_notify_new_transactions(int command, NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_NEW_TRANSACTIONS (" 
       + std::to_string(arg.txs.size())
       + " txes)"
       );
    for (const auto &blob: arg.txs) {
      const auto r = cryptonote::maybe_tx_and_hash_from_blob(blob);
      if (r) {
        const auto& [tx, hash] = *r;
        LOG_P2P_MESSAGE("Including transaction " + hash.to_str());
      }
    }
    if(context.m_state != cryptonote_connection_context::state_normal)
      return 1;

    // while syncing, core will lock for a long time, so we ignore
    // those txes as they aren't really needed anyway, and avoid a
    // long block before replying
    if(!is_synchronized())
    {
      LOG_DEBUG_CC(context, "Received new tx while syncing, ignored");
      return 1;
    }

    std::vector<cryptonote::string_blob> newtxs;
    newtxs.reserve(arg.txs.size());
    for (size_t i = 0; i < arg.txs.size(); ++i)
    {
      cryptonote::tx_verification_context tvc{};
      m_core.handle_incoming_ringct({arg.txs[i], crypto::null_hash}, tvc, relay_method::fluff, true);
      if(tvc.m_verifivation_failed)
      {
        LOG_PRINT_CCONTEXT_L1("Tx verification failed, dropping connection");
        drop_connection(context, false, false);
        return 1;
      }
      if(tvc.m_should_be_relayed)
        newtxs.push_back(std::move(arg.txs[i]));
    }
    arg.txs = std::move(newtxs);

    if(arg.txs.size())
    {
      //TODO: add announce usage here
      relay_transactions(arg, context.m_connection_id, context.m_remote_address.get_zone());
    }

    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_request_get_objects(int command, NOTIFY_REQUEST_GET_OBJECTS::request& arg, cryptonote_connection_context& context)
  {
    if (context.m_state == cryptonote_connection_context::state_before_handshake)
    {
      LOG_ERROR_CCONTEXT("Requested objects before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_REQUEST_GET_OBJECTS ("
       + std::to_string(arg.blocks.size())
       + " blocks)"
       );
    if (arg.blocks.size() > CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT)
      {
        LOG_ERROR_CCONTEXT
          (
            "Requested objects count is too big ("
            + std::to_string(arg.blocks.size())
            + ") expected not more then "
            + std::to_string(CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT)
           );
        drop_connection(context, false, false);
        return 1;
      }

    NOTIFY_RESPONSE_GET_OBJECTS::request rsp;
    if(!m_core.handle_get_objects(arg, rsp, context))
    {
      LOG_ERROR_CCONTEXT("failed to handle request NOTIFY_REQUEST_GET_OBJECTS, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    context.m_last_request_time = std::chrono::system_clock::now();
    LOG_P2P_MESSAGE
      (
       "-->>NOTIFY_RESPONSE_GET_OBJECTS: blocks.size()="
       + std::to_string(rsp.blocks.size())
       + ", rsp.m_current_blockchain_height="
       + std::to_string(rsp.current_blockchain_height)
       + ", missed_ids.size()="
       + std::to_string(rsp.missed_ids.size())
       );
    post_notify<NOTIFY_RESPONSE_GET_OBJECTS>(rsp, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------



  int t_cryptonote_protocol_handler::handle_response_get_objects(int command, NOTIFY_RESPONSE_GET_OBJECTS::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_RESPONSE_GET_OBJECTS ("
       + std::to_string(arg.blocks.size())
       + " blocks)"
       );
    LOG_PEER_STATE("received objects");

    std::chrono::time_point<std::chrono::system_clock> request_time = context.m_last_request_time;
    context.m_last_request_time = std::chrono::system_clock::time_point::min();

    if (context.m_expect_response != NOTIFY_RESPONSE_GET_OBJECTS::ID)
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_GET_OBJECTS out of the blue, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    context.m_expect_response = 0;

    // calculate size of request
    size_t size = 0;
    size_t blocks_size = 0;
    for (const auto &element : arg.blocks) {
      blocks_size += element.block.size();
      for (const auto &tx : element.txs)
        blocks_size += tx.blob.size();
    }
    size += blocks_size;

    for (const auto &element : arg.missed_ids)
      size += sizeof(element.data);

    size += sizeof(arg.current_blockchain_height);
    ++m_sync_spans_downloaded;
    m_sync_download_objects_size += size;
    LOG_DEBUG
      (
       context.to_str()
       + " downloaded "
       + std::to_string(size)
       + " bytes worth of blocks"
       );

    /*using namespace std::chrono;
      auto point = steady_clock::now();
      auto time_from_epoh = point.time_since_epoch();
      auto sec = duration_cast< seconds >( time_from_epoh ).count();*/

    if(arg.blocks.empty())
    {
      LOG_ERROR_CCONTEXT("sent wrong NOTIFY_HAVE_OBJECTS: no blocks");
      drop_connection(context, true, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }
    if(context.m_last_response_height > arg.current_blockchain_height)
    {
      LOG_ERROR_CCONTEXT
        (
         "sent wrong NOTIFY_HAVE_OBJECTS: arg.m_current_blockchain_height="
         + std::to_string(arg.current_blockchain_height)
         + " < m_last_response_height="
         + std::to_string(context.m_last_response_height)
         + ", dropping connection"
         );
      drop_connection(context, false, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }

    if (arg.current_blockchain_height < context.m_remote_blockchain_height)
    {
      LOG_INFO
        (
         context.to_str()
         + "Claims "
         + std::to_string(arg.current_blockchain_height)
         + ", claimed "
         + std::to_string(context.m_remote_blockchain_height)
         + " before"
         );
      hit_score(context, 1);
    }
    context.m_remote_blockchain_height = arg.current_blockchain_height;
    if (context.m_remote_blockchain_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(context.m_remote_blockchain_height);

    std::vector<crypto::hash> block_hashes;
    block_hashes.reserve(arg.blocks.size());
    const std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    uint64_t start_height = std::numeric_limits<uint64_t>::max();
    cryptonote::block b;
    for(const block_complete_entry& block_entry: arg.blocks)
    {
      if (m_stopping)
      {
        return 1;
      }

      const auto r = maybe_block_and_hash_from_blob(block_entry.block);
      if(!r)
      {
        LOG_ERROR_CCONTEXT
          (
           "sent wrong block: failed to parse and validate block: "
           + epee::string_tools::buff_to_hex_nodelimer(block_entry.block)
           + ", dropping connection"
           );
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      const auto& [b, block_hash] = *r;
      if (!(is_coinbase(b.miner_tx)))
      {
        LOG_ERROR_CCONTEXT
          (
           "sent wrong block: block: miner tx does not have exactly one txin_gen input"
          + epee::string_tools::buff_to_hex_nodelimer(block_entry.block)
           + ", dropping connection"
           );
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      if (start_height == std::numeric_limits<uint64_t>::max())
      {
        start_height = boost::get<txin_gen>(b.miner_tx.vin[0]).height;
        if (start_height > context.m_expect_height)
        {
          LOG_ERROR_CCONTEXT("sent block ahead of expected height, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
      }

      auto req_it = context.m_requested_objects.find(block_hash);
      if(req_it == context.m_requested_objects.end())
      {
        LOG_ERROR_CCONTEXT
          (
           "sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id="
           + epee::string_tools::pod_to_hex(get_blob_hash(block_entry.block))
           + " wasn't requested, dropping connection"
           );
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }
      if(b.tx_hashes.size() != block_entry.txs.size())
      {
        LOG_ERROR_CCONTEXT
          (
           "sent wrong NOTIFY_RESPONSE_GET_OBJECTS: block with id="
           + epee::string_tools::pod_to_hex(get_blob_hash(block_entry.block))
           + ", tx_hashes.size()="
           + std::to_string(b.tx_hashes.size())
           + " mismatch with block_complete_entry.m_txs.size()="
           + std::to_string(block_entry.txs.size())
           + ", dropping connection"
           );
        drop_connection(context, false, false);
        ++m_sync_bad_spans_downloaded;
        return 1;
      }

      context.m_requested_objects.erase(req_it);
      block_hashes.push_back(block_hash);
    }

    if(!context.m_requested_objects.empty())
    {
      LOG_ERROR
        (
         context.to_str()
         + "returned not all requested objects (context.m_requested_objects.size()="
         + std::to_string(context.m_requested_objects.size())
         + "), dropping connection"
         );
      drop_connection(context, false, false);
      ++m_sync_bad_spans_downloaded;
      return 1;
    }

    const bool pruned_ok = false;
    if (!pruned_ok)
    {
      // if we don't want pruned data, check we did not get any
      for (block_complete_entry& block_entry: arg.blocks)
      {
        if (block_entry.pruned)
        {
          LOG_ERROR(context.to_str() + "returned a pruned block, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
        if (block_entry.block_weight)
        {
          LOG_ERROR(context.to_str() + "returned a block weight for a non pruned block, dropping connection");
          drop_connection(context, false, false);
          ++m_sync_bad_spans_downloaded;
          return 1;
        }
        for (const tx_blob_entry &tx_entry: block_entry.txs)
        {
          if (tx_entry.prunable_hash != crypto::null_hash)
          {
            LOG_ERROR(context.to_str() + "returned at least one pruned object which we did not expect, dropping connection");
            drop_connection(context, false, false);
            ++m_sync_bad_spans_downloaded;
            return 1;
          }
        }
      }
    }

    {
      LOG_COLOR
        (
         epee::yellow
         , epee::LogLevel::Debug
         , context.to_str()
         + " Got NEW BLOCKS inside of "
         + std::string(__FUNCTION__)
         + ": size: "
         + std::to_string(arg.blocks.size())
         + ", blocks: "
         + std::to_string(start_height)
         + " - "
         + std::to_string(start_height + arg.blocks.size() - 1)
         );

      // add that new span to the block queue
      const auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - request_time);
      const float rate = size * 1e6 / (dt.count() + 1);
      LOG_DEBUG_MUTE(context << " adding span: " << arg.blocks.size() << " at height " << start_height << ", " << dt.count()/1e6 << " seconds, " << (rate/1024) << " kB/s");
      m_block_queue.add_blocks(start_height, arg.blocks, context.m_connection_id, context.m_remote_address, rate, blocks_size);

      const crypto::hash last_block_hash = cryptonote::get_block_hash(b);
      context.m_last_known_hash = last_block_hash;
    }

    try_add_next_blocks(context);
    return 1;
  }

  int t_cryptonote_protocol_handler::try_add_next_blocks(cryptonote_connection_context& context)
  {
    bool force_next_batch = false;

    {
      // We try to lock the sync lock. If we can, it means no other thread is
      // currently adding blocks, so we do that for as long as we can from the
      // block queue. Then, we go back to download.
      const std::unique_lock<std::mutex> sync{m_sync_lock, std::try_to_lock};
      if (!sync.owns_lock())
      {
        LOG_INFO
          (
           context.to_str()
           + "Failed to lock m_sync_lock, going back to download"
           );
        goto skip;
      }
      LOG_DEBUG(context.to_str() + " lock m_sync_lock, adding blocks to chain...");
      LOG_PEER_STATE("adding blocks");

      {
        m_core.pause_mine();
        bool starting = true;
        epee::misc_utils::auto_scope_leave_caller scope_exit_handler = epee::misc_utils::create_scope_leave_handler([this, &starting]() {
          m_core.resume_mine();
          if (!starting)
            m_last_add_end_time = epee::misc_utils::get_ns_count();
        });

        while (1)
        {
          const uint64_t previous_height = m_core.get_current_blockchain_height();
          const auto maybe_next_batch = m_block_queue.get_next_batch();

          if (!maybe_next_batch)
          {
            LOG_DEBUG(context.to_str() + " no next span found, going back to download");
            break;
          }

          const auto&
            [start_height, blocks, span_connection_id, span_origin]
            = *maybe_next_batch;

          if (blocks.empty())
          {
            LOG_ERROR(context.to_str() + "Next span has no blocks");
            m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
            continue;
          }

          LOG_DEBUG_MUTE(context << " next span in the queue has blocks " << start_height << "-" << (start_height + blocks.size() - 1)
              << ", we need " << previous_height);

          const auto r = maybe_block_and_hash_from_blob(blocks.back().block);
          if (!r)
          {
            LOG_ERROR(context.to_str() + "Failed to parse block, but it should already have been parsed");
            m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
            continue;
          }
          const auto last_block_hash = r->second;

          if (m_core.have_block(last_block_hash))
          {
            const uint64_t subchain_height = start_height + blocks.size();
            LOG_DEBUG_CC
              (
               context
               , "These are old blocks, ignoring: blocks "
               + std::to_string(start_height)
               + " - "
               + std::to_string(subchain_height-1)
               + ", blockchain height "
               + std::to_string(m_core.get_current_blockchain_height())
               );
            m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
            ++m_sync_old_spans_downloaded;
            continue;
          }

          const auto maybeBlock = maybe_block_from_blob(blocks.front().block);
          if (!maybeBlock)
          {
            LOG_ERROR(context.to_str() + "Failed to parse block, but it should already have been parsed");
            m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
            continue;
          }
          const auto& new_block = *maybeBlock;
          bool parent_known = m_core.have_block(new_block.prev_id);
          if (!parent_known)
          {
            // it could be:
            //  - later in the current chain
            //  - later in an alt chain
            //  - orphan
            // if it was requested, then it'll be resolved later, otherwise it's an orphan
            constexpr bool parent_requested = false;
            if (!parent_requested)
            {
              // this can happen if a connection was sicced onto a late span, if it did not have those blocks,
              // since we don't know that at the sic time
              LOG_ERROR_CCONTEXT("Got block with unknown parent which was not requested - querying block hashes");
              m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
              context.m_needed_objects.clear();
              context.m_last_response_height = 0;
              goto skip;
            }

            // parent was requested, so we wait for it to be retrieved
            LOG_INFO
              (
               context.to_str() + " parent was requested, we'll get back to it"
               );
            break;
          }

          const std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();

          if (starting)
          {
            starting = false;
            if (m_last_add_end_time)
            {
              const uint64_t tnow = epee::misc_utils::get_ns_count();
              const uint64_t ns = tnow - m_last_add_end_time;
              LOG_INFO
                (
                 "Restarting adding block after idle for "
                 + std::to_string(ns/1e9)
                 + " seconds");
            }
          }

          std::vector<block> pblocks;
          if (!m_core.prepare_handle_incoming_blocks(blocks, pblocks))
          {
            LOG_ERROR_CCONTEXT("Failure in prepare_handle_incoming_blocks");
            drop_bad_connections(span_origin);
            return 1;
          }
          if (!pblocks.empty() && pblocks.size() != blocks.size())
          {
            m_core.cleanup_handle_incoming_blocks();
            LOG_ERROR_CCONTEXT("Internal error: blocks.size() != block_entry.txs.size()");
            return 1;
          }

          size_t blockidx = 0;
          for(const block_complete_entry& block_entry: blocks)
          {
            if (m_stopping)
            {
                m_core.cleanup_handle_incoming_blocks();
                return 1;
            }

            // process transactions
            std::vector<tx_verification_context> tvc;
            m_core.handle_incoming_ringcts(block_entry.txs, tvc, relay_method::block, true);
            if (tvc.size() != block_entry.txs.size())
            {
              LOG_ERROR_CCONTEXT("Internal error: tvc.size() != block_entry.txs.size()");
              if (!m_core.cleanup_handle_incoming_blocks())
              {
                LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
                return 1;
              }
              return 1;
            }
            std::vector<tx_blob_entry>::const_iterator it = block_entry.txs.begin();
            for (size_t i = 0; i < tvc.size(); ++i, ++it)
            {
              if(tvc[i].m_verifivation_failed)
              {
                drop_bad_connections(span_origin);
                if (!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t f)->bool{
                  const auto r = cryptonote::maybe_tx_and_hash_from_blob(it->blob);
                  if (r) {
                    const auto& [tx, txid] = *r;
                    LOG_ERROR_CCONTEXT
                      (
                       "transaction verification failed on NOTIFY_RESPONSE_GET_OBJECTS, tx_id = "
                       + epee::string_tools::pod_to_hex(txid)
                       + ", dropping connection"
                       );
                  }
                  drop_connection(context, false, true);
                  return 1;
                }))
                  LOG_ERROR_CCONTEXT("span connection id not found");

                if (!m_core.cleanup_handle_incoming_blocks())
                {
                  LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
                  return 1;
                }
                // in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
                m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
                return 1;
              }
            }

            // process block

            block_verification_context bvc = {};

            m_core.handle_incoming_block(block_entry.block, pblocks.empty() ? NULL : &pblocks[blockidx], bvc, false); // <--- process block

            if(bvc.m_verifivation_failed)
            {
              drop_bad_connections(span_origin);
              if (!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t f)->bool{
                LOG_PRINT_CCONTEXT_L1("Block verification failed, dropping connection");
                drop_connection_with_score(context, bvc.m_bad_pow ? P2P_IP_FAILS_BEFORE_BLOCK : 1, true);
                return 1;
              }))
                LOG_ERROR_CCONTEXT("span connection id not found");

              if (!m_core.cleanup_handle_incoming_blocks())
              {
                LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
                return 1;
              }

              // in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
              m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
              return 1;
            }
            if(bvc.m_marked_as_orphaned)
            {
              drop_bad_connections(span_origin);
              if (!m_p2p->for_connection(span_connection_id, [&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t f)->bool{
                LOG_PRINT_CCONTEXT_L1("Block received at sync phase was marked as orphaned, dropping connection");
                drop_connection(context, true, true);
                return 1;
              }))
                LOG_ERROR_CCONTEXT("span connection id not found");

              if (!m_core.cleanup_handle_incoming_blocks())
              {
                LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
                return 1;
              }

              // in case the peer had dropped beforehand, remove the span anyway so other threads can wake up and get it
              m_block_queue.remove_batches_from_connection(span_connection_id, start_height);
              return 1;
            }

            ++blockidx;

          } // each download block

          if (!m_core.cleanup_handle_incoming_blocks())
          {
            LOG_PRINT_CCONTEXT_L0("Failure in cleanup_handle_incoming_blocks");
            return 1;
          }

          m_block_queue.remove_batches_from_connection(span_connection_id, start_height);

          const uint64_t current_blockchain_height = m_core.get_current_blockchain_height();
          if (current_blockchain_height > previous_height)
          {
            const uint64_t target_blockchain_height = m_core.get_target_blockchain_height();
            const auto dt = std::chrono::duration_cast<std::chrono::microseconds>
              (std::chrono::system_clock::now() - start);
            std::string progress_message = "";
            if (current_blockchain_height < target_blockchain_height)
            {
              uint64_t completion_percent = (current_blockchain_height * 100 / target_blockchain_height);
              if (completion_percent == 100) // never show 100% if not actually up to date
                completion_percent = 99;
              progress_message = " (" + std::to_string(completion_percent) + "%, "
                  + std::to_string(target_blockchain_height - current_blockchain_height) + " left";
              progress_message += ")";
            }

            const auto sync_rate = (current_blockchain_height - previous_height) * 1e6 / dt.count();
            const std::string timing_message = std::string(" \t[")
              + std::to_string(static_cast<uint32_t>(sync_rate))
              + " blocks/sec]";

            // if (ELPP->vRegistry()->allowed(epee::LogLevel::Debug, "sync-info"))
            //   timing_message += std::string(": ") + m_block_queue.get_overview(current_blockchain_height);
            LOG_CATEGORY_COLOR
              (
               epee::LogLevel::Info
               , epee::GLOBAL_CATEGORY
               , epee::yellow
               , "Synced "
               + std::to_string(current_blockchain_height)
               + "/"
               + std::to_string(target_blockchain_height)
               + progress_message
               + timing_message
               );
          }
        }
      }

      LOG_PEER_STATE("stopping adding blocks");

      if (should_download_next_batch(context, false))
      {
        force_next_batch = true;
      }
    }

skip:
    if (!request_missing_objects(context, true, force_next_batch))
    {
      LOG_ERROR_CCONTEXT("Failed to request missing objects, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::on_idle()
  {
    m_idle_peer_kicker.do_call(std::bind(&t_cryptonote_protocol_handler::kick_idle_peers, this));
    m_standby_checker.do_call(std::bind(&t_cryptonote_protocol_handler::check_standby_peers, this));
    m_sync_search_checker.do_call(std::bind(&t_cryptonote_protocol_handler::update_sync_search, this));
    return m_core.on_idle();
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::kick_idle_peers()
  {
    LOG_TRACE("Checking for idle peers...");
    std::vector<std::pair<boost::uuids::uuid, unsigned>> idle_peers;
    m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (context.m_state == cryptonote_connection_context::state_synchronizing && context.m_last_request_time != std::chrono::system_clock::time_point::min())
      {
        const std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
        const auto dt = std::chrono::duration_cast<std::chrono::microseconds>(now - context.m_last_request_time);
        const auto ms = dt.count();
        if (ms > IDLE_PEER_KICK_TIME || (context.m_expect_response && ms > NON_RESPONSIVE_PEER_KICK_TIME))
        {
          if (context.m_score-- >= 0)
          {
            LOG_INFO
              (
               context.to_str()
               + " kicking idle peer, last update "
               + std::to_string(dt.count() / 1.e6)
               + " seconds ago, expecting "
               + std::to_string((int)context.m_expect_response)
               );
            LOG_PRINT_CCONTEXT_L2("requesting callback");
            context.m_last_request_time = std::chrono::system_clock::time_point::min();
            context.m_expect_response = 0;
            context.m_expect_height = 0;
            context.m_state = cryptonote_connection_context::state_standby; // we'll go back to adding, then (if we can't), download
            ++context.m_callback_request_count;
            m_p2p->request_callback(context);
          }
          else
          {
            idle_peers.push_back(std::make_pair(context.m_connection_id, context.m_expect_response == 0 ? 1 : 5));
          }
        }
      }
      return true;
    });

    for (const auto &e: idle_peers)
    {
      const auto &uuid = e.first;
      m_p2p->for_connection(uuid, [&](cryptonote_connection_context& ctx, nodetool::peerid_type peer_id, uint32_t f)->bool{
        LOG_INFO(ctx.to_str() +  "dropping idle peer with negative score");
        drop_connection_with_score(ctx, e.second, false);
        return true;
      });
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::update_sync_search()
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target > height) // if we're not synced yet, don't do it
      return true;

    LOG_TRACE("Checking for outgoing syncing peers...");
    unsigned n_syncing = 0, n_synced = 0;
    boost::uuids::uuid last_synced_peer_id(boost::uuids::nil_uuid());
    m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (!peer_id || context.m_is_income) // only consider connected outgoing peers
        return true;
      if (context.m_state == cryptonote_connection_context::state_synchronizing)
        ++n_syncing;
      if (context.m_state == cryptonote_connection_context::state_normal)
      {
        ++n_synced;
        if (!context.m_anchor)
          last_synced_peer_id = context.m_connection_id;
      }
      return true;
    });
    LOG_TRACE
      (
       std::to_string(n_syncing)
       + " syncing, "
       + std::to_string(n_synced)
       + " synced"
       );

    // if we're at max out peers, and not enough are syncing
    if (n_synced + n_syncing >= m_max_out_peers && n_syncing < P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT && last_synced_peer_id != boost::uuids::nil_uuid())
    {
      if (!m_p2p->for_connection(last_synced_peer_id, [&](cryptonote_connection_context& ctx, nodetool::peerid_type peer_id, uint32_t f)->bool{
        LOG_INFO
          (
           ctx.to_str()
           + "dropping synced peer, "
           + std::to_string(n_syncing)
           + " syncing, "
           + std::to_string(n_synced)
           + " synced"
           );
        drop_connection(ctx, false, false);
        return true;
      }))
        LOG_DEBUG("Failed to find peer we wanted to drop");
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::check_standby_peers()
  {
    m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
    {
      if (context.m_state == cryptonote_connection_context::state_standby)
      {
        LOG_PRINT_CCONTEXT_L2("requesting callback");
        ++context.m_callback_request_count;
        m_p2p->request_callback(context);
      }
      return true;
    });
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_request_chain(int command, NOTIFY_REQUEST_CHAIN::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_REQUEST_CHAIN ("
       + std::to_string(arg.block_ids.size())
       + " blocks"
       );
    if (context.m_state == cryptonote_connection_context::state_before_handshake)
    {
      LOG_ERROR_CCONTEXT("Requested chain before handshake, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }
    NOTIFY_RESPONSE_CHAIN_ENTRY::request r;
    if(!m_core.find_blockchain_supplement(arg.block_ids, r))
    {
      LOG_ERROR_CCONTEXT("Failed to handle NOTIFY_REQUEST_CHAIN.");
      return 1;
    }
    LOG_P2P_MESSAGE
      (
       "-->>NOTIFY_RESPONSE_CHAIN_ENTRY: m_start_height="
       + std::to_string(r.start_height)
       + ", m_total_height="
       + std::to_string(r.total_height)
       + ", m_block_ids.size()="
       + std::to_string(r.m_block_ids.size())
       );
    post_notify<NOTIFY_RESPONSE_CHAIN_ENTRY>(r, context);
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::should_download_next_batch(cryptonote_connection_context& context, bool standby)
  {
    const uint64_t blockchain_height = m_core.get_current_blockchain_height();
    if (context.m_remote_blockchain_height <= blockchain_height)
      return false;
    {
      if (!m_block_queue.has_next_batch(blockchain_height))
      {
        LOG_DEBUG(context.to_str() + " we should download it as no peer reserved it");
        return true;
      }
    }

    return false;
  }
  //------------------------------------------------------------------------------------------------------------------------

  size_t t_cryptonote_protocol_handler::skip_unneeded_hashes(cryptonote_connection_context& context, bool check_block_queue) const
  {
    // take out blocks we already have
    size_t skip = 0;
    while
      (
       skip < context.m_needed_objects.size()
       && m_core.have_block(context.m_needed_objects[skip].first)
       )
    {
      // if we're popping the last hash, record it so we can ask again from that hash,
      // this prevents never being able to progress on peers we get old hash lists from
      if (skip + 1 == context.m_needed_objects.size())
        context.m_last_known_hash = context.m_needed_objects[skip].first;
      ++skip;
    }
    if (skip > 0)
    {
      LOG_DEBUG
        (
         context.to_str()
         + "skipping "
         + std::to_string(skip)
         + "/"
         + std::to_string(context.m_needed_objects.size())
         + " blocks"
         );
      context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>
        (std::next(context.m_needed_objects.begin(), skip), context.m_needed_objects.end());
    }
    return skip;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::request_missing_objects(cryptonote_connection_context& context, bool check_having_blocks, bool force_next_batch)
  {
    // if we don't need to get next span, and the block queue is full enough, wait a bit
    bool start_from_current_chain = false;

    LOG_DEBUG_MUTE(context << " request_missing_objects: check " << check_having_blocks << ", force_next_batch " << force_next_batch
        << ", m_needed_objects " << context.m_needed_objects.size() << " lrh " << context.m_last_response_height << ", chain "
           << m_core.get_current_blockchain_height());

    if(context.m_needed_objects.size() || force_next_batch)
    {
      //we know objects that we need, request this objects
      NOTIFY_REQUEST_GET_OBJECTS::request req;
      bool is_next = false;
      size_t count = 0;
      const size_t count_limit = constant::BLOCKS_SYNCHRONIZING_SIZE;
      std::optional<std::pair<uint64_t, uint64_t>> maybe_span;
      if (force_next_batch)
      {
        if (!maybe_span)
        {
          maybe_span = m_block_queue.get_next_span_if_scheduled();
          if (maybe_span)
          {
            is_next = true;
            m_block_queue.reset_next_batch_time();
          }
        }
      }
      if (!maybe_span)
      {
        LOG_DEBUG(context.to_str() + " span size is 0");
        if (context.m_last_response_height + 1 < context.m_needed_objects.size())
        {
          LOG_ERROR
            (
             context.to_str()
             + " ERROR: inconsistent context: lrh "
             + std::to_string(context.m_last_response_height)
             + ", nos "
             + std::to_string(context.m_needed_objects.size())
             );
          context.m_needed_objects.clear();
          context.m_last_response_height = 0;
          goto skip;
        }
        if (skip_unneeded_hashes(context, false) && context.m_needed_objects.empty() && context.m_num_requested == 0)
        {
          LOG_ERROR(context.to_str() + "Nothing we can request from this peer, and we did not request anything previously");
          return false;
        }

        const uint64_t first_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
        maybe_span = m_block_queue.reserve_blocks
          (
           first_block_height
           , context.m_last_response_height
           , count_limit
           , context.m_connection_id
           , context.m_remote_address
           , context.m_remote_blockchain_height
           , context.m_needed_objects
           );
        if (maybe_span) {
          const auto span = *maybe_span;
        LOG_DEBUG
          (
           context.to_str()
           + " span from "
           + std::to_string(first_block_height)
           + ": "
           + std::to_string(span.first)
           + "/"
           + std::to_string(span.second)
           );
        }
      }
      if ((!maybe_span) && !force_next_batch)
      {
        LOG_DEBUG
          (
           context.to_str()
           + " still no span reserved, we may be in the corner case of next span scheduled and everything else scheduled/filled"
           );
        maybe_span = m_block_queue.get_next_span_if_scheduled();
        if (maybe_span)
        {
          is_next = true;
        }
      }
      if (maybe_span)
      {
        const auto span = *maybe_span;

        LOG_DEBUG
          (
           context.to_str()
           + " span: "
           + std::to_string(span.first)
           + "/"
           + std::to_string(span.second)
           + " ("
           + std::to_string(span.first)
           + " - "
           + std::to_string(span.first + span.second - 1)
           + ")"
           );

        if (!is_next)
        {
          const uint64_t first_context_block_height = context.m_last_response_height - context.m_needed_objects.size() + 1;
          uint64_t skip = span.first - first_context_block_height;
          if (skip > context.m_needed_objects.size())
          {
            LOG_ERROR
              (
               "ERROR: skip "
               + std::to_string(skip)
               + ", m_needed_objects "
               + std::to_string(context.m_needed_objects.size())
               + ", first_context_block_height"
               + std::to_string(first_context_block_height)
               );
            return false;
          }
          if (skip > 0)
            context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>
              (std::next(context.m_needed_objects.begin(), skip), context.m_needed_objects.end());
          if (context.m_needed_objects.size() < span.second)
          {
            LOG_ERROR
              (
               "ERROR: span "
               + std::to_string(span.first)
               + "/"
               + std::to_string(span.second)
               + ", m_needed_objects "
               + std::to_string(context.m_needed_objects.size())
               );
            return false;
          }

          req.blocks.reserve(req.blocks.size() + span.second);
          for (size_t n = 0; n < span.second; ++n)
          {
            req.blocks.push_back(context.m_needed_objects[n].first);
            ++count;
            context.m_requested_objects.insert(context.m_needed_objects[n].first);
          }
          context.m_needed_objects = std::vector<std::pair<crypto::hash, uint64_t>>
            (std::next(context.m_needed_objects.begin(), span.second), context.m_needed_objects.end());
        }

        context.m_last_request_time = std::chrono::system_clock::now();
        context.m_expect_height = span.first;
        context.m_expect_response = NOTIFY_RESPONSE_GET_OBJECTS::ID;
        LOG_P2P_MESSAGE
          (
           "-->>NOTIFY_REQUEST_GET_OBJECTS: blocks.size()="
           + std::to_string(req.blocks.size())
           + "requested blocks count="
           + std::to_string(count)
           + " / "
           + std::to_string(count_limit)
           + " from "
           + std::to_string(span.first)
           + ", first hash "
           + req.blocks.front().to_str()
           );

        post_notify<NOTIFY_REQUEST_GET_OBJECTS>(req, context);
        LOG_PEER_STATE("requesting objects");
        return true;
      }
    }

skip:
    context.m_needed_objects.clear();

    // we might have been called from the "received chain entry" handler, and end up
    // here because we can't use any of those blocks (maybe because all of them are
    // actually already requested). In this case, if we can add blocks instead, do so
    if (m_core.get_current_blockchain_height() < m_core.get_target_blockchain_height())
    {
      const std::unique_lock<std::mutex> sync{m_sync_lock, std::try_to_lock};
      if (sync.owns_lock())
      {
        const auto maybe_next_batch = m_block_queue.get_next_batch();

        if (maybe_next_batch)
        {
          LOG_DEBUG_CC(context, "No other thread is adding blocks, resuming");
          LOG_PEER_STATE("will try to add blocks next");
          context.m_state = cryptonote_connection_context::state_standby;
          ++context.m_callback_request_count;
          m_p2p->request_callback(context);
          return true;
        }
      }
    }

    if(context.m_last_response_height < context.m_remote_blockchain_height-1)
    {//we have to fetch more objects ids, request blockchain entry

      NOTIFY_REQUEST_CHAIN::request r = {};
      context.m_expect_height = m_core.get_current_blockchain_height();
      m_core.get_short_chain_history(r.block_ids);
      LOG_ERROR_AND_RETURN_UNLESS(!r.block_ids.empty(), false, "Short chain history is empty");

      if (!start_from_current_chain)
      {
        // we'll want to start off from where we are on that peer, which may not be added yet
        if (context.m_last_known_hash != crypto::null_hash && r.block_ids.front() != context.m_last_known_hash)
        {
          context.m_expect_height = std::numeric_limits<uint64_t>::max();
          r.block_ids.push_front(context.m_last_known_hash);
        }
      }

      //std::string blob; // for calculate size of request
      //epee::serialization::store_t_to_binary(r, blob);
      //LOG_PRINT_CCONTEXT_L1("r = " << 200);

      context.m_last_request_time = std::chrono::system_clock::now();
      context.m_expect_response = NOTIFY_RESPONSE_CHAIN_ENTRY::ID;
      LOG_P2P_MESSAGE
        (
         "-->>NOTIFY_REQUEST_CHAIN: m_block_ids.size()="
         + std::to_string(r.block_ids.size())
         + ", start_from_current_chain "
         + std::to_string(start_from_current_chain)
         );
      post_notify<NOTIFY_REQUEST_CHAIN>(r, context);
      LOG_PEER_STATE("requesting chain");
    }else
    {
      LOG_ERROR_AND_RETURN_UNLESS
        (
         context.m_last_response_height == context.m_remote_blockchain_height-1
         && !context.m_needed_objects.size()
         && !context.m_requested_objects.size()
         , false
         , std::string()
         + "request_missing_blocks final condition failed!"
         + "\r\nm_last_response_height="
         + std::to_string(context.m_last_response_height)
         + "\r\nm_remote_blockchain_height="
         + std::to_string(context.m_remote_blockchain_height)
         + "\r\nm_needed_objects.size()="
         + std::to_string(context.m_needed_objects.size())
         + "\r\nm_requested_objects.size()="
         + std::to_string(context.m_requested_objects.size())
         + "\r\non connection ["
         + epee::net_utils::print_connection_context_short(context)
         + "]"
         );

      context.m_state = cryptonote_connection_context::state_normal;
      if (context.m_remote_blockchain_height >= m_core.get_target_blockchain_height())
      {
        if (m_core.get_current_blockchain_height() >= m_core.get_target_blockchain_height())
        {
          LOG_CATEGORY_COLOR
            (
             epee::LogLevel::Info
             , epee::GLOBAL_CATEGORY
             , epee::green
             , "SYNCHRONIZED OK"
             );
          on_connection_synchronized();
        }
      }
      else
      {
        LOG_INFO
          (
           context.to_str()
           + " we've reached this peer's blockchain height (theirs "
           + std::to_string(context.m_remote_blockchain_height)
           + ", our target "
           + std::to_string(m_core.get_target_blockchain_height())
           );
      }
    }
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::on_connection_synchronized()
  {
    bool val_expected = false;
    if(m_synchronized.compare_exchange_strong(val_expected, true))
    {
      LOG_CATEGORY_COLOR
        (
         epee::LogLevel::Info
         , epee::GLOBAL_CATEGORY
         , epee::yellow
         , "**********************************************************************"
         );

      LOG_CATEGORY_COLOR
        (
         epee::LogLevel::Info
         , epee::GLOBAL_CATEGORY
         , epee::yellow
         , "You are now synchronized with the network. You may now start lolnero."
         );

      LOG_CATEGORY_COLOR
        (
         epee::LogLevel::Info
         , epee::GLOBAL_CATEGORY
         , epee::yellow
         , "**********************************************************************"
         );

      m_core.on_synchronized();
    }
    m_core.safesyncmode(true);

    // ask for txpool complement from any suitable node if we did not yet
    val_expected = true;
    if (m_ask_for_txpool_complement.compare_exchange_strong(val_expected, false))
    {
      m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool
      {
        if(context.m_state < cryptonote_connection_context::state_synchronizing)
        {
          LOG_DEBUG(context.to_str() +  "not ready, ignoring");
          return true;
        }
        if (!request_txpool_complement(context))
        {
          LOG_ERROR(context.to_str() + "Failed to request txpool complement");
          return true;
        }
        return false;
      });
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  size_t t_cryptonote_protocol_handler::get_synchronizing_connections_count()
  {
    size_t count = 0;
    m_p2p->for_each_connection([&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
      if(context.m_state == cryptonote_connection_context::state_synchronizing)
        ++count;
      return true;
    });
    return count;
  }
  //------------------------------------------------------------------------------------------------------------------------

  int t_cryptonote_protocol_handler::handle_response_chain_entry(int command, NOTIFY_RESPONSE_CHAIN_ENTRY::request& arg, cryptonote_connection_context& context)
  {
    LOG_P2P_MESSAGE
      (
       "Received NOTIFY_RESPONSE_CHAIN_ENTRY: m_block_ids.size()="
       + std::to_string(arg.m_block_ids.size())
       + ", m_start_height="
       + std::to_string(arg.start_height)
       + ", m_total_height="
       + std::to_string(arg.total_height)
       );
    LOG_PEER_STATE("received chain");

    if (context.m_expect_response != NOTIFY_RESPONSE_CHAIN_ENTRY::ID)
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_CHAIN_ENTRY out of the blue, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    context.m_expect_response = 0;
    if (arg.start_height + 1 > context.m_expect_height) // we expect an overlapping block
    {
      LOG_ERROR_CCONTEXT("Got NOTIFY_RESPONSE_CHAIN_ENTRY past expected height, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }

    context.m_last_request_time = std::chrono::system_clock::time_point::min();

    m_sync_download_chain_size += arg.m_block_ids.size() * sizeof(crypto::hash);

    if(!arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent empty m_block_ids, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    if (arg.total_height < arg.m_block_ids.size() || arg.start_height > arg.total_height - arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent invalid start/nblocks/height, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    if (!arg.m_block_weights.empty() && arg.m_block_weights.size() != arg.m_block_ids.size())
    {
      LOG_ERROR_CCONTEXT("sent invalid block weight array, dropping connection");
      drop_connection(context, true, false);
      return 1;
    }
    LOG_DEBUG
      (
       context.to_str()
       + "first block hash "
       + arg.m_block_ids.front().to_str()
       + ", last "
       + arg.m_block_ids.back().to_str()
       );

    if (arg.total_height >= CRYPTONOTE_MAX_BLOCK_NUMBER || arg.m_block_ids.size() > BLOCKS_IDS_SYNCHRONIZING_MAX_COUNT)
    {
      LOG_ERROR_CCONTEXT
        (
         "sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with total_height="
         + std::to_string(arg.total_height)
         + ", m_block_ids.size()="
         + std::to_string(arg.m_block_ids.size())
         );
      drop_connection(context, false, false);
      return 1;
    }
    if (arg.total_height < context.m_remote_blockchain_height)
    {
      LOG_INFO
        (
         context.to_str()
         + "Claims "
         + std::to_string(arg.total_height)
         + ", claimed "
         + std::to_string(context.m_remote_blockchain_height)
         + " before"
         );
      hit_score(context, 1);
    }
    context.m_remote_blockchain_height = arg.total_height;
    context.m_last_response_height = arg.start_height + arg.m_block_ids.size()-1;
    if(context.m_last_response_height > context.m_remote_blockchain_height)
    {
      LOG_ERROR_CCONTEXT
        (
         "sent wrong NOTIFY_RESPONSE_CHAIN_ENTRY, with m_total_height="
         + std::to_string(arg.total_height)
         + ", m_start_height="
         + std::to_string(arg.start_height)
         + ", m_block_ids.size()="
         + std::to_string(arg.m_block_ids.size())
         );
      drop_connection(context, false, false);
      return 1;
    }

    context.m_needed_objects.clear();
    context.m_needed_objects.reserve(arg.m_block_ids.size());
    std::unordered_set<crypto::hash> blocks_found;
    bool first = true;
    bool expect_unknown = false;
    for (size_t i = 0; i < arg.m_block_ids.size(); ++i)
    {
      if (!blocks_found.insert(arg.m_block_ids[i]).second)
      {
        LOG_ERROR_CCONTEXT("Duplicate blocks in chain entry response, dropping connection");
        drop_connection_with_score(context, 5, false);
        return 1;
      }
      int where;
      const bool have_block = m_core.have_block_unlocked(arg.m_block_ids[i], &where);
      if (first)
      {
        if (!have_block)
        {
          LOG_ERROR_CCONTEXT("First block hash is unknown, dropping connection");
          drop_connection_with_score(context, 5, false);
          return 1;
        }
      }
      if (!first)
      {
        // after the first, blocks may be known or unknown, but if they are known,
        // they should be at the same height if on the main chain
        if (have_block)
        {
          switch (where)
          {
            default:
            case HAVE_BLOCK_INVALID:
              LOG_ERROR_CCONTEXT("Block is invalid or known without known type, dropping connection");
              drop_connection(context, true, false);
              return 1;
            case HAVE_BLOCK_MAIN_CHAIN:
              if (expect_unknown)
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              if (m_core.get_block_id_by_height(arg.start_height + i) != arg.m_block_ids[i])
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but not at the expected height, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              break;
            case HAVE_BLOCK_ALT_CHAIN:
              if (expect_unknown)
              {
                LOG_ERROR_CCONTEXT("Block is on the main chain, but we did not expect a known block, dropping connection");
                drop_connection_with_score(context, 5, false);
                return 1;
              }
              break;
          }
        }
        else
          expect_unknown = true;
      }
      const uint64_t block_weight = arg.m_block_weights.empty() ? 0 : arg.m_block_weights[i];
      context.m_needed_objects.push_back(std::make_pair(arg.m_block_ids[i], block_weight));
      first = false;
    }

    if (!request_missing_objects(context, false))
    {
      LOG_ERROR_CCONTEXT("Failed to request missing objects, dropping connection");
      drop_connection(context, false, false);
      return 1;
    }

    if (arg.total_height > m_core.get_target_blockchain_height())
      m_core.set_target_blockchain_height(arg.total_height);

    context.m_num_requested = 0;
    return 1;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::relay_block(NOTIFY_NEW_BLOCK::request& arg, cryptonote_connection_context& exclude_context)
  {
    NOTIFY_NEW_FLUFFY_BLOCK::request fluffy_arg = AUTO_VAL_INIT(fluffy_arg);
    fluffy_arg.current_blockchain_height = arg.current_blockchain_height;
    std::vector<tx_blob_entry> fluffy_txs;
    fluffy_arg.b = arg.b;
    fluffy_arg.b.txs = fluffy_txs;

    // sort peers between fluffy ones and others
    std::vector<std::pair<epee::net_utils::zone, boost::uuids::uuid>> fullConnections, fluffyConnections;
    m_p2p->for_each_connection([this, &exclude_context, &fullConnections, &fluffyConnections](connection_context& context, nodetool::peerid_type peer_id, uint32_t support_flags)
    {
      // peer_id also filters out connections before handshake
      if (peer_id && exclude_context.m_connection_id != context.m_connection_id && context.m_remote_address.get_zone() == epee::net_utils::zone::public_)
      {
        if(m_core.fluffy_blocks_enabled() && (support_flags & P2P_SUPPORT_FLAG_FLUFFY_BLOCKS))
        {
          LOG_DEBUG_CC(context, "PEER SUPPORTS FLUFFY BLOCKS - RELAYING THIN/COMPACT WHATEVER BLOCK");
          fluffyConnections.push_back({context.m_remote_address.get_zone(), context.m_connection_id});
        }
        else
        {
          LOG_DEBUG_CC(context, "PEER DOESN'T SUPPORT FLUFFY BLOCKS - RELAYING FULL BLOCK");
          fullConnections.push_back({context.m_remote_address.get_zone(), context.m_connection_id});
        }
      }
      return true;
    });

    // send fluffy ones first, we want to encourage people to run that
    if (!fluffyConnections.empty())
    {
      std::string fluffyBlob;
      epee::serialization::store_t_to_binary(fluffy_arg, fluffyBlob);
      m_p2p->relay_notify_to_list(NOTIFY_NEW_FLUFFY_BLOCK::ID, epee::string_tools::string_to_blob(fluffyBlob), std::move(fluffyConnections));
    }
    if (!fullConnections.empty())
    {
      std::string fullBlob;
      epee::serialization::store_t_to_binary(arg, fullBlob);
      m_p2p->relay_notify_to_list(NOTIFY_NEW_BLOCK::ID, epee::string_tools::string_to_blob(fullBlob), std::move(fullConnections));
    }

    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::relay_transactions(NOTIFY_NEW_TRANSACTIONS::request& arg, const boost::uuids::uuid& source, epee::net_utils::zone zone)
  {
    /* Push all outgoing transactions to this function. The behavior needs to
       identify how the transaction is going to be relayed, and then update the
       local mempool before doing the relay. The code was already updating the
       DB twice on received transactions - it is difficult to workaround this
       due to the internal design. */
    return m_p2p->send_txs(std::move(arg.txs), zone, source, m_core) != epee::net_utils::zone::invalid;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::request_txpool_complement(cryptonote_connection_context &context)
  {
    NOTIFY_GET_TXPOOL_COMPLEMENT::request r = {};
    if (!m_core.get_pool_transaction_hashes(r.hashes, false))
    {
      LOG_ERROR("Failed to get txpool hashes");
      return false;
    }
    LOG_P2P_MESSAGE
      (
       "-->>NOTIFY_GET_TXPOOL_COMPLEMENT: hashes.size()="
       + std::to_string(r.hashes.size())
       );
    post_notify<NOTIFY_GET_TXPOOL_COMPLEMENT>(r, context);
    LOG_PEER_STATE("requesting txpool complement");
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::hit_score(cryptonote_connection_context &context, int32_t score)
  {
    if (score <= 0)
    {
      LOG_ERROR("Negative score hit");
      return;
    }
    context.m_score -= score;
    if (context.m_score <= DROP_PEERS_ON_SCORE)
      drop_connection_with_score(context, 5, false);
  }
  //------------------------------------------------------------------------------------------------------------------------

  std::string t_cryptonote_protocol_handler::get_peers_overview() const
  {
    std::stringstream ss;
    const std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    m_p2p->for_each_connection([&](const connection_context &ctx, nodetool::peerid_type peer_id, uint32_t support_flags) {
      char state_char = cryptonote::get_protocol_state_char(ctx.m_state);
      ss << state_char;
      if (ctx.m_last_request_time != std::chrono::system_clock::time_point::min()) {
        const auto dt = std::chrono::duration_cast<std::chrono::microseconds>(now - ctx.m_last_request_time);
        ss << ((dt.count() > IDLE_PEER_KICK_TIME) ? "!" : "?");
      }
      ss <<  + " ";
      return true;
    });
    return ss.str();
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::needs_new_sync_connections() const
  {
    const uint64_t target = m_core.get_target_blockchain_height();
    const uint64_t height = m_core.get_current_blockchain_height();
    if (target && target <= height)
      return false;
    size_t n_out_peers = 0;
    m_p2p->for_each_connection([&](cryptonote_connection_context& ctx, nodetool::peerid_type peer_id, uint32_t support_flags)->bool{
      if (!ctx.m_is_income)
        ++n_out_peers;
      return true;
    });
    if (n_out_peers >= m_max_out_peers)
      return false;
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------

  bool t_cryptonote_protocol_handler::is_busy_syncing()
  {
    const std::unique_lock<std::mutex> sync{m_sync_lock, std::try_to_lock};
    return !sync.owns_lock();
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::drop_connection_with_score(cryptonote_connection_context &context, unsigned score, bool flush_all_spans)
  {
    LOG_DEBUG_CC
      (
       context
       , "dropping connection id "
       + boost::uuids::to_string(context.m_connection_id)
       + ", score "
       + std::to_string(score)
       + ", flush_all_spans "
       + std::to_string(flush_all_spans)
       );

    if (flush_all_spans) {
      m_block_queue
        .remove_batches_from_connection(context.m_connection_id);
    }


    // copy since dropping the connection will invalidate the context, and thus the address
    const auto remote_address = context.m_remote_address;

    m_p2p->drop_connection(context);

    if (score > 0)
      m_p2p->add_host_fail(remote_address, score);
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::drop_connection(cryptonote_connection_context &context, bool add_fail, bool flush_all_spans)
  {
    return drop_connection_with_score(context, add_fail ? 1 : 0, flush_all_spans);
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::drop_bad_connections(const epee::net_utils::network_address address)
  {
    LOG_WARNING("dropping bad connections to " + address.str());

    m_p2p->add_host_fail(address, 5);

    std::vector<boost::uuids::uuid> drop;
    m_p2p->for_each_connection([&](const connection_context& cntxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
      if (address.is_same_host(cntxt.m_remote_address))
        drop.push_back(cntxt.m_connection_id);
      return true;
    });
    for (const boost::uuids::uuid &id: drop)
    {
      m_block_queue.remove_batches_from_connection(id);
      m_p2p->for_connection(id, [&](cryptonote_connection_context& context, nodetool::peerid_type peer_id, uint32_t f)->bool{
        drop_connection(context, true, false);
        return true;
      });
    }
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::on_connection_new(cryptonote_connection_context &context)
  {
    context.set_max_bytes(nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>::ID, 65536);
    context.set_max_bytes(nodetool::COMMAND_TIMED_SYNC_T<cryptonote::CORE_SYNC_DATA>::ID, 65536);
    context.set_max_bytes(nodetool::COMMAND_PING::ID, 4096);
    context.set_max_bytes(nodetool::COMMAND_SUPPORT_FLAGS::ID, 4096);

    context.set_max_bytes(cryptonote::NOTIFY_NEW_BLOCK::ID, 1024 * 1024 * 128); // 128 MB (max packet is a bit less than 100 MB though)
    context.set_max_bytes(cryptonote::NOTIFY_NEW_TRANSACTIONS::ID, 1024 * 1024 * 128); // 128 MB (max packet is a bit less than 100 MB though)
    context.set_max_bytes(cryptonote::NOTIFY_REQUEST_GET_OBJECTS::ID, 1024 * 1024 * 2); // 2 MB
    context.set_max_bytes(cryptonote::NOTIFY_RESPONSE_GET_OBJECTS::ID, 1024 * 1024 * 128); // 128 MB (max packet is a bit less than 100 MB though)
    context.set_max_bytes(cryptonote::NOTIFY_REQUEST_CHAIN::ID, 512 * 1024); // 512 kB
    context.set_max_bytes(cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::ID, 1024 * 1024 * 4); // 4 MB
    context.set_max_bytes(cryptonote::NOTIFY_NEW_FLUFFY_BLOCK::ID, 1024 * 1024 * 4); // 4 MB, but it does not includes transaction data
    context.set_max_bytes(cryptonote::NOTIFY_REQUEST_FLUFFY_MISSING_TX::ID, 1024 * 1024); // 1 MB
    context.set_max_bytes(cryptonote::NOTIFY_GET_TXPOOL_COMPLEMENT::ID, 1024 * 1024 * 4); // 4 MB
  }
  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::on_connection_close(cryptonote_connection_context &context)
  {
    uint64_t target = 0;
    m_p2p->for_each_connection([&](const connection_context& cntxt, nodetool::peerid_type peer_id, uint32_t support_flags) {
      if (cntxt.m_state >= cryptonote_connection_context::state_synchronizing && cntxt.m_connection_id != context.m_connection_id)
        target = std::max(target, cntxt.m_remote_blockchain_height);
      return true;
    });

    if (!m_stopping) {
      const uint64_t previous_target = m_core.get_target_blockchain_height();
      if (target < previous_target)
        {
          LOG_INFO
            (
             "Target height decreasing from "
             + std::to_string(previous_target)
             + " to "
             + std::to_string(target)
             );
          m_core.set_target_blockchain_height(target);
          if (target == 0 && context.m_state > cryptonote_connection_context::state_before_handshake && !m_stopping)
            {
              LOG_GLOBAL("lolnerod is now disconnected from the network");
              m_ask_for_txpool_complement = true;
            }
        }
    }

    LOG_PEER_STATE("closed");
  }

  //------------------------------------------------------------------------------------------------------------------------

  void t_cryptonote_protocol_handler::stop()
  {
    m_stopping = true;
    m_core.stop();
  }
} // namespace
