/*

Copyright (c) 2020-2021, The Lolnero Project

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/


#include "sha3.hpp"

#include "opencl/kernel_sha3.h"

#include "error.hpp"

#include <iostream>


namespace opencl
{

std::optional<cl::Device> getGPU() {
  std::vector<cl::Platform> platforms;
  cl::Platform::get(&platforms);

  if (platforms.empty()) {
    std::cerr << "No OpenCL platforms" << std::endl;
    // std::terminate();
    return {};
  }

  // std::cout << "Platform size: " << platforms.size() << std::endl;

  const auto platform = platforms.front();

  std::vector<cl::Device> devices;
  platform.getDevices(CL_DEVICE_TYPE_GPU, &devices);

  if (devices.empty()) {
    return {};
  }

  // std::cout << "devices size: " << devices.size() << std::endl;

  const cl::Device device = devices.front();
  return device;
}

std::optional
<
  std::pair<cl::Program, cl::CommandQueue>
  >
getSha3Program
(
 const cl::Device device
 , const cl::Context context
 ) {

  const std::string src
    (
     (const char*)opencl_kernel_sha3_cl
     , opencl_kernel_sha3_cl_len
     );

  // constexpr std::basic_string_view<uint8_t> src = opencl_kernel_sha3_cl;

  // std::cout << "Running kernel: \n" << src << std::endl;

  cl::Program::Sources sources(1, {src.data(), src.length()});

  cl::Program program(context, sources);

	const auto err = program.build("-cl-std=CL1.2");
  if (err != CL_SUCCESS) {
    std::cerr
      << "OpenCL compilation error:" << std::endl
      << getErrorString(err)
      << std::endl;

    if (err == CL_BUILD_PROGRAM_FAILURE) {
      // Determine the size of the log
      // cl_build_status status = program.getBuildInfo<CL_PROGRAM_BUILD_STATUS>(device);

      // Get the build log
      std::string name     = device.getInfo<CL_DEVICE_NAME>();
      std::string buildlog = program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(device);
      std::cerr << "Build log for " << name << ":" << std::endl
                << buildlog << std::endl;
    }
    return {};
	}

	const cl::CommandQueue queue(context, device);
  return {{program, queue}};
}

std::vector<cl_mining_return> opencl_sha3
(
 const cl_mining_template x
 , const size_t worker_size
 , const cl::Context context
 , const cl::Program program
 , const cl::CommandQueue queue
)
{
	cl::Kernel sha3_kernel(program, "sha3");
  const size_t N = worker_size;

  cl_mining_template mining_template = x;

	std::vector<cl_mining_return> mining_return(N);
  const size_t return_size = mining_return.size() * sizeof(cl_mining_return);


	// std::vector<uint8_t> templateHead(templateHeadSize);

	// Allocate device buffers and transfer input data to device.
	cl::Buffer mining_template_array
    (
     context
     , CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR
     , sizeof(cl_mining_template)
     , &mining_template
     );

	cl::Buffer mining_return_array
    (
     context
     , CL_MEM_READ_WRITE
     , return_size
     );

	// Set kernel parameters.
	sha3_kernel.setArg(0, static_cast<uint64_t>(N));
	sha3_kernel.setArg(1, mining_template_array);
	sha3_kernel.setArg(2, mining_return_array);
	sha3_kernel.setArg(3, mining_template.tailSize);

	// Launch kernel on the compute device.
	queue.enqueueNDRangeKernel(sha3_kernel, cl::NullRange, N, cl::NullRange);

	// Get result back to host.
	queue.enqueueReadBuffer
    (
     mining_return_array
     , CL_TRUE
     , 0
     , return_size
     , mining_return.data()
     );

  return mining_return;
}

}
