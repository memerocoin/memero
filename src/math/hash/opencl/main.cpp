/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include <iostream>
#include <fstream>
#include <string_view>
#include <cstdint>
#include <exception>
#include <array>
#include <optional>
#include <span>

#include "sha3.hpp"


std::string blob_to_string(const std::span<const uint8_t> x) {
  return std::string((const char*)x.data(), x.size());
}

int main() {
  using namespace opencl;

  const auto maybeGpu = getGPU();

  if (!maybeGpu) {
    std::cerr << "No OpenCL capable GPUs" << std::endl;
    std::terminate();
  }

  const auto device = *maybeGpu;
  const cl::Context context(device);

  const auto maybeProgram = getSha3Program(device, context);

  if (!maybeProgram) {
    std::cerr << "Failed to build sha3 OpenCL kernel" << std::endl;
    std::terminate();
  }

  const auto [program, queue] = *maybeProgram;

  cl_mining_template mining_template;

  std::fill
    (
     mining_template.header.begin()
     , mining_template.header.end()
     , 1
     );

  mining_template.nonce = 0;
  mining_template.loopSize = 1;

  std::fill
    (
     mining_template.hashBound.begin()
     , mining_template.hashBound.end()
     , 255
     );

  std::fill
    (
     mining_template.tail.begin()
     , mining_template.tail.end()
     , 2
     );

  const size_t worker_size = 32;
  const auto hashes = opencl_sha3
    (
     mining_template
     , worker_size
     , context
     , program
     , queue
     );

	std::cout << "finished!" << std::endl;

  const auto r = hashes[0];

	std::cout << "hash: " << std::endl;
  for (const uint8_t c: r.hash) {
    std::cout << std::hex << (uint16_t)c;
  }
  std::cout << std::endl;

  const bool valid = r.valid;
  std::cout << "nonce: " << r.nonce << std::endl;
	std::cout << "valid: " << valid << std::endl;

  // std::cout << std::endl;
  // constexpr uint8_t zero = 8;
  // std::cout << "0: " << (uint16_t)zero << std::endl;
  // std::cout << std::hex << mining_return[0].hash;

  return 0;
}
