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


#include "tools/epee/include/file_io_utils.h"

namespace epee
{
  namespace file_io_utils
  {
    bool save_string_to_file(const std::string& path_to_file, const std::string& str)
    {
      try
      {
        std::ofstream fstream;
        fstream.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        fstream.open(path_to_file, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
        fstream << str;
        fstream.close();
        return true;
      }

      catch(...)
      {
        return false;
      }
    }

    bool load_file_to_string(const std::string& path_to_file, std::string& target_str, size_t max_size)
    {
      try
      {
        std::ifstream fstream;
        fstream.exceptions(std::ifstream::failbit | std::ifstream::badbit);
        fstream.open(path_to_file, std::ios_base::binary | std::ios_base::in | std::ios::ate);

        std::ifstream::pos_type file_size = fstream.tellg();

        if((uint64_t)file_size > (uint64_t)max_size) // ensure a large domain for comparison, and negative -> too large
          return false;//don't go crazy
        size_t file_size_t = static_cast<size_t>(file_size);

        target_str.resize(file_size_t);

        fstream.seekg (0, std::ios::beg);
        fstream.read((char*)target_str.data(), target_str.size());
        fstream.close();
        return true;
      }

      catch(...)
      {
        return false;
      }
    }

  }
}
