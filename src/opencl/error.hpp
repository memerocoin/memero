#pragma once

#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.hpp>

const char *getErrorString(cl_int error);
