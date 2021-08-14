// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#pragma once

#include <thread>
#include <algorithm>

#include <boost/utility/value_init.hpp>

namespace epee
{

#define AUTO_VAL_INIT(v)   boost::value_initialized<decltype(v)>()

namespace misc_utils
{
  template<typename t_iterator>
  t_iterator move_it_backward(t_iterator it, size_t count)
  {
    while(count--)
      it--;
    return it;
  }


	inline
	bool sleep_no_w(long ms )
	{
		std::this_thread::sleep_for
      (std::chrono::milliseconds(ms));

		return true;
	}

  // need copy by value, since std::nth_element will modify the element in place
  template<class t>
  t median(std::vector<t> v)
  {
    if(v.empty())
      return boost::value_initialized<t>();

    if(v.size() == 1)
      return v[0];

    const size_t n = v.size() / 2;
    std::nth_element(v.begin(), std::next(v.begin(), n), v.end());
    return v[n];
  }

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

  struct call_before_die_base
  {
    virtual ~call_before_die_base(){}
  };

  typedef std::unique_ptr<call_before_die_base> auto_scope_leave_caller;


  template<class t_scope_leave_handler>
  struct call_before_die: public call_before_die_base
  {
    t_scope_leave_handler m_func;
    call_before_die(t_scope_leave_handler f):m_func(f)
    {}
    ~call_before_die()
    {
      try { m_func(); }
      catch (...) { /* ignore */ }
    }
  };

  template<class t_scope_leave_handler>
  auto_scope_leave_caller create_scope_leave_handler(t_scope_leave_handler f)
  {
    return std::make_unique<call_before_die<t_scope_leave_handler>>(f);
  }

  template<typename T> struct struct_init: T
  {
    struct_init(): T{} {}
  };

}
}
