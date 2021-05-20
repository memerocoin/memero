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

/*! \file json_archive.h
 *
 * \brief JSON archive
 */

#include "json_archive.h"

void json_archive<true>::serialize_blob(const void *buf, const size_t len) {
  begin_string();
  for (size_t i = 0; i < len; i++) {
    unsigned char c = ((unsigned char *)buf)[i];
    stream_ << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  }
  end_string();
}


void json_archive<true>::begin_string()
{
  const char* delimiter = "\"";
  stream_ << delimiter;
}

void json_archive<true>::end_string()
{
  const char* delimiter = "\"";
  stream_ << delimiter;
}

void json_archive<true>::begin_array(size_t s)
{
  inner_array_size_ = s;
  ++depth_;
  stream_ << "[ ";
}

void json_archive<true>::delimit_array()
{
  stream_ << ", ";
}

void json_archive<true>::end_array()
{
  --depth_;
  if (0 < inner_array_size_)
  {
    make_indent();
  }
  stream_ << "]";
}

void json_archive<true>::write_variant_tag(const char *t)
{
  tag(t);
}

