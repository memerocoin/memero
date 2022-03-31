/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#include "tools/epee/include/string_file.hpp"

#include <fstream>
#include <filesystem>


namespace epee
{
  namespace string_file
  {

    // https://www.boost.org/doc/libs/1_78_0/boost/filesystem/string_file.hpp

    bool save_string_to_file(const std::string& p, const std::string& str)
    {
      try
        {
          std::ofstream file;
          file.exceptions(std::ios_base::failbit | std::ios_base::badbit);
          file.open(p, std::ios_base::binary);
          file.write(str.c_str(), str.size());
          return true;
        }

      catch(...)
        {
          return false;
        }
    }

    std::optional<std::string> load_file_to_string
    (const std::string& p)
    {
      try
      {
        std::string str;
        std::ifstream file;
        file.exceptions(std::ios_base::failbit | std::ios_base::badbit);
        file.open(p, std::ios_base::binary);
        std::size_t sz =
          static_cast< std::size_t >(std::filesystem::file_size(p));
        str.resize(sz, '\0');
        file.read(&str[0], sz);
        return str;
      }

      catch(...)
      {
        return {};
      }
    }

  }
}
