// (C) Copyright 2002 Robert Ramey - http://www.rrsd.com .
// Use, modification and distribution is subject to the Boost Software
// License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

# pragma once

#include <climits>
#if CHAR_BIT != 8
#error This code assumes an eight-bit byte.
#endif

namespace boost { namespace archive {

enum portable_binary_archive_flags {
    endian_big        = 0x4000,
    endian_little     = 0x8000
};


void reverse_bytes(signed char size, char *address);

} }
