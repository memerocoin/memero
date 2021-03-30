/// @file
/// @author rfree (current maintainer in monero.cc project)
/// @brief This is the place to implement our handlers for protocol network actions, e.g. for ratelimit for download-requests

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

#include <string>
#include <vector>

#include <memory>

#include "tools/epee/include/syncobj.h"

#include "tools/epee/include/net/net_utils_base.h" 
#include "tools/epee/include/misc_log_ex.h" 
#include <chrono>
#include <thread> 
#include "tools/epee/include/misc_language.h"

#include <algorithm>


#include "cryptonote_protocol_handler.h"


#include "cryptonote/core/cryptonote_core.h" // e.g. for the send_stop_signal()

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "net.cn"

// ################################################################################################
// ################################################################################################
// the "header part". Not separated out for .hpp because point of this modification is 
// to rebuild just 1 translation unit while working on this code.
// (But maybe common parts will be separated out later though - if needed)
// ################################################################################################
// ################################################################################################

namespace cryptonote {

class cryptonote_protocol_handler_base_pimpl { // placeholer if needed
	public:

};

} // namespace

// ################################################################################################
// ################################################################################################
// ################################################################################################
// ################################################################################################

namespace cryptonote { 

cryptonote_protocol_handler_base::cryptonote_protocol_handler_base() {
}

cryptonote_protocol_handler_base::~cryptonote_protocol_handler_base() {
}

void cryptonote_protocol_handler_base::handler_request_blocks_history(std::list<crypto::hash>& ids) {
}

void cryptonote_protocol_handler_base::handler_response_blocks_now(size_t packet_size) {
	using namespace epee::net_utils;
	MDEBUG("Packet size: " << packet_size);
}

} // namespace


