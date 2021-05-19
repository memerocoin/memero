// (C) Copyright 2002 Robert Ramey - http://www.rrsd.com .
// Use, modification and distribution is subject to the Boost Software
// License, Version 1.0. (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include "portable_binary_archive.hpp"

namespace boost {
namespace archive {

  void reverse_bytes(signed char size, char *address){
    if (size <= 0)
      throw archive_exception(archive_exception::other_exception);
    char * first = address;
    char * last = first + size - 1;
    for(;first < last;++first, --last){
      char x = *last;
      *last = *first;
      *first = x;
    }
  }

}
}
