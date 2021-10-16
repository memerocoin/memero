#!/usr/bin/env bash

cd src
xxd -i opencl/kernel/sha3.cl > opencl/kernel_sha3.h
