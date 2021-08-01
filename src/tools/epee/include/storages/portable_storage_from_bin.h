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

#include "portable_storage_base.h"
#include "portable_storage_bin_utils.h"

#include "tools/epee/include/misc_log_ex.h"

#ifdef EPEE_PORTABLE_STORAGE_RECURSION_LIMIT
#define EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL EPEE_PORTABLE_STORAGE_RECURSION_LIMIT
#else
#define EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL 100
#endif

namespace epee
{
  namespace serialization
  {
    template<typename T>
    struct ps_min_bytes {
      static constexpr const size_t strict = 4096; // actual low bound
    };
    template<> struct ps_min_bytes<uint64_t> { static constexpr const size_t strict = 8; };
    template<> struct ps_min_bytes<int64_t> { static constexpr const size_t strict = 8; };
    template<> struct ps_min_bytes<uint32_t> { static constexpr const size_t strict = 4; };
    template<> struct ps_min_bytes<int32_t> { static constexpr const size_t strict = 4; };
    template<> struct ps_min_bytes<uint16_t> { static constexpr const size_t strict = 2; };
    template<> struct ps_min_bytes<int16_t> { static constexpr const size_t strict = 2; };
    template<> struct ps_min_bytes<uint8_t> { static constexpr const size_t strict = 1; };
    template<> struct ps_min_bytes<int8_t> { static constexpr const size_t strict = 1; };
    template<> struct ps_min_bytes<double> { static constexpr const size_t strict = 8; };
    template<> struct ps_min_bytes<bool> { static constexpr const size_t strict = 1; };
    template<> struct ps_min_bytes<std::string> { static constexpr const size_t strict = 2; };
    template<> struct ps_min_bytes<section> { static constexpr const size_t strict = 1; };
    template<> struct ps_min_bytes<array_entry> { static constexpr const size_t strict = 1; };

    struct throwable_buffer_reader
    {
      throwable_buffer_reader(const void* ptr, size_t sz);
      void read(void* target, size_t count);
      void read_sec_name(std::string& sce_name);
      template<class t_pod_type>
      void read(t_pod_type& pod_val);
      template<class t_type>
      t_type read();
      template<class type_name>
      storage_entry read_ae();
      storage_entry load_storage_array_entry(uint8_t type);
      size_t read_varint();
      template<class t_type>
      storage_entry read_se();
      storage_entry load_storage_entry();
      void read(section& sec);
      void read(std::string& str);
      void read(array_entry &ae);
      template<class t_type>
      size_t min_bytes() const;
      void set_limits(size_t objects, size_t fields, size_t strings);
    private:
      struct recursuion_limitation_guard
      {
        size_t& m_counter_ref;
        recursuion_limitation_guard(size_t& counter):m_counter_ref(counter)
        {
          ++m_counter_ref;
          LOG_ERROR_AND_THROW_IF(m_counter_ref < EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL, "Wrong blob data in portable storage: recursion limitation (" << EPEE_PORTABLE_STORAGE_RECURSION_LIMIT_INTERNAL << ") exceeded");
        }
        ~recursuion_limitation_guard() noexcept(false)
        {
          LOG_ERROR_AND_THROW_IF(m_counter_ref != 0, "Internal error: m_counter_ref == 0 while ~recursuion_limitation_guard()");
          --m_counter_ref;
        }
      };
#define RECURSION_LIMITATION()  recursuion_limitation_guard rl(m_recursion_count)

      const uint8_t* m_ptr;
      size_t m_count;
      size_t m_recursion_count;
      size_t m_objects;
      size_t m_fields;
      size_t m_strings;

      size_t max_objects;
      size_t max_fields;
      size_t max_strings;
    };

    template<class t_pod_type>
    void throwable_buffer_reader::read(t_pod_type& pod_val)
    {
      RECURSION_LIMITATION();
      static_assert(std::is_standard_layout<t_pod_type>::value, "standard layout type expected");
      static_assert(std::is_trivial<t_pod_type>::value, "trivial type expected");
      read(&pod_val, sizeof(pod_val));
      pod_val = CONVERT_POD(pod_val);
    }

    template<class t_type>
    t_type throwable_buffer_reader::read()
    {
      RECURSION_LIMITATION();
      t_type v;
      read(v);
      return v;
    }


    template<class type_name>
    storage_entry throwable_buffer_reader::read_ae()
    {
      RECURSION_LIMITATION();
      //for pod types
      array_entry_t<type_name> sa;
      size_t size = read_varint();
      LOG_ERROR_AND_THROW_IF(size <= m_count / ps_min_bytes<type_name>::strict, "Size sanity check failed");
      if (std::is_same<type_name, section>())
      {
        LOG_ERROR_AND_THROW_IF(size <= max_objects - m_objects, "Too many objects");
        m_objects += size;
      }
      else if (std::is_same<type_name, std::string>())
      {
        LOG_ERROR_AND_THROW_IF(size <= max_strings - m_strings, "Too many strings");
        m_strings += size;
      }

      sa.reserve(size);
      //TODO: add some optimization here later
      while(size--)
        sa.m_array.push_back(read<type_name>());
      return storage_entry(array_entry(std::move(sa)));
    }

    template<class t_type>
    storage_entry throwable_buffer_reader::read_se()
    {
      RECURSION_LIMITATION();
      t_type v;
      read(v);
      return storage_entry(v);
    }

    template<>
    storage_entry throwable_buffer_reader::read_se<std::string>();

    template<>
    storage_entry throwable_buffer_reader::read_se<section>();

    template<>
    storage_entry throwable_buffer_reader::read_se<array_entry>();

  }
}
