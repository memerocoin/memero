/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#pragma once

#include <cstdint>
#include <array>
#include <optional>

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.hpp>

namespace opencl
{

  constexpr size_t templateHeaderSize = 39;
  constexpr size_t templateTailMaxSize = 36;
  constexpr size_t hashSize = 32;

  struct cl_mining_template
  {
    uint64_t nonce = 0;
    std::array<uint8_t, hashSize> hashBound;
    std::array<uint8_t, templateHeaderSize> header = {};
    std::array<uint8_t, templateTailMaxSize> tail = {};
    size_t tailSize = 0;
    size_t loopSize = 0;
  };


  constexpr size_t nonceSize = sizeof(uint64_t);

  struct cl_mining_return
  {
    std::array<uint8_t, hashSize> hash;
    uint64_t nonce;
    uint8_t valid;
  };


  std::optional<cl::Device> getGPU();

  std::optional
  <
    std::pair<cl::Program, cl::CommandQueue>
    > getSha3Program
  (
   const cl::Device device
   , const cl::Context context
   );

  std::vector<cl_mining_return> opencl_sha3
  (
   const cl_mining_template x
   , const size_t worker_size
   , const cl::Context context
   , const cl::Program program
   , const cl::CommandQueue queue
   );

}
