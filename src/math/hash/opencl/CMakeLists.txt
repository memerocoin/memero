add_library(opencl-sha3
  error.cpp
  sha3.cpp
  )

target_link_libraries(opencl-sha3
  OpenCL::OpenCL
  )

install(TARGETS opencl-sha3)

if(BUILD_TESTING)
  add_executable(opencl-sha3-test
    main.cpp
    )

  target_link_libraries(opencl-sha3-test
    OpenCL::OpenCL
    opencl-sha3
    )

  set_property(TARGET opencl-sha3-test
    PROPERTY
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

  set_property(TARGET opencl-sha3-test
    PROPERTY
    OUTPUT_NAME "opencl-sha3-test")

  install(TARGETS opencl-sha3-test DESTINATION bin)
endif()

# configure_file(opencl/kernel/sha3.cl kernel COPYONLY)


