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

#include "binary_archive.h"

void binary_archive<false>::begin_array(size_t &s)
{
  serialize_varint(s);
}

void binary_archive<false>::serialize_blob(void *buf, size_t len)
{
  stream_.read((char *)buf, len);
}

void binary_archive<false>::read_variant_tag(variant_tag_type &t) {
  serialize_int(t);
}

size_t binary_archive<false>::remaining_bytes() {
  if (!stream_.good())
    return 0;
  //std::cerr << "tell: " << stream_.tellg() << std::endl;
  assert(stream_.tellg() <= eof_pos_);
  return eof_pos_ - stream_.tellg();
}


void binary_archive<true>::serialize_blob(const void *buf, size_t len)
{
  stream_.write((const char *)buf, len);
}

void binary_archive<true>::begin_array(size_t s)
{
  serialize_varint(s);
}

void binary_archive<true>::write_variant_tag(variant_tag_type t) {
  serialize_int(t);
}
