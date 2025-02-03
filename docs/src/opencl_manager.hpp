#pragma once

#define CL_HPP_MINIMUM_OPENCL_VERSION 200
#define CL_HPP_TARGET_OPENCL_VERSION 200
#define CL_HPP_ENABLE_EXCEPTIONS

#include <CL/opencl.hpp>

class OpenCLManager {
public:
    cl::Context context;
    cl::Program program;
    cl::CommandQueue queue;
    
    void initialize();
    void loadKernels();
}; 