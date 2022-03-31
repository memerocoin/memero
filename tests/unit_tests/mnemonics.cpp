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

#include "gtest/gtest.h"
#include "tools/epee/functional/wipeable_string.hpp"
#include "math/crypto/functional/key.hpp"
#include <stdlib.h>
#include <vector>
#include <time.h>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include "wallet/mnemonics/language_base.h"
#include "wallet/mnemonics/electrum-words.h"
#include "wallet/mnemonics/english.h"

TEST(mnemonics, consistency)
{
  try {
    std::vector<std::string> language_list;
    crypto::ElectrumWords::get_language_list(language_list);
  }
  catch(const std::exception &e)
  {
    std::cout << "Error initializing mnemonics: " << e.what() << std::endl;
    ASSERT_TRUE(false);
  }
}

TEST(mnemonics, utf8prefix)
{
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("foo"), 0) == "");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("foo"), 1) == "f");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("foo"), 2) == "fo");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("foo"), 3) == "foo");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("foo"), 4) == "foo");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("æon"), 0) == "");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("æon"), 1) == "æ");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("æon"), 2) == "æo");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("æon"), 3) == "æon");
  ASSERT_TRUE(Language::utf8prefix(epee::wipeable_string("æon"), 4) == "æon");
}

TEST(mnemonics, partial_word_tolerance)
{
    bool res;
    //
    crypto::secret_key key_1;
    std::string language_name_1;
    const std::string seed_1 = "crim bam scamp gna limi woma wron tuit birth mundane donuts square cohesive dolphin titans narrate fue saved wrap aloof magic mirr toget upda wra";
    res = crypto::ElectrumWords::words_to_bytes(seed_1, key_1, language_name_1);
    ASSERT_EQ(true, res);
    ASSERT_STREQ(language_name_1.c_str(), "English");
}
