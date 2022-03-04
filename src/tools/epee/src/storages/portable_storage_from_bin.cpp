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



#include "tools/epee/include/storages/portable_storage_from_bin.h"

namespace epee
{
  namespace serialization
  {
    throwable_buffer_reader::throwable_buffer_reader(const void* ptr, size_t sz)
    {
      if(!ptr)
        throw std::runtime_error("throwable_buffer_reader: ptr==nullptr");
      if(!sz)
        throw std::runtime_error("throwable_buffer_reader: sz==0");
      m_ptr = (uint8_t*)ptr;
      m_count = sz;
      m_recursion_count = 0;
      m_objects = 0;
      m_fields = 0;
      m_strings = 0;
      max_objects = std::numeric_limits<size_t>::max();
      max_fields = std::numeric_limits<size_t>::max();
      max_strings = std::numeric_limits<size_t>::max();
    }

    void throwable_buffer_reader::read(void* target, size_t count)
    {
      RECURSION_LIMITATION();
      LOG_ERROR_AND_THROW_UNLESS
        (
         m_count >= count
         , std::string(" attempt to read ")
         + std::to_string(count)
         + " bytes from buffer with "
         + std::to_string(m_count)
         + " bytes remained"
         );
      memcpy(target, m_ptr, count);
      m_ptr += count;
      m_count -= count;
    }

    void throwable_buffer_reader::read_sec_name(std::string& sce_name)
    {
      RECURSION_LIMITATION();
      uint8_t name_len = 0;
      read(name_len);
      LOG_ERROR_AND_THROW_UNLESS(name_len > 0, "Section name is missing");
      sce_name.resize(name_len);
      read((void*)sce_name.data(), name_len);
    }

    storage_entry throwable_buffer_reader::load_storage_array_entry(uint8_t type)
    {
      RECURSION_LIMITATION();
      type &= ~SERIALIZE_FLAG_ARRAY;
      switch(type)
      {
      case SERIALIZE_TYPE_INT64:  return read_ae<int64_t>();
      case SERIALIZE_TYPE_INT32:  return read_ae<int32_t>();
      case SERIALIZE_TYPE_INT16:  return read_ae<int16_t>();
      case SERIALIZE_TYPE_INT8:   return read_ae<int8_t>();
      case SERIALIZE_TYPE_UINT64: return read_ae<uint64_t>();
      case SERIALIZE_TYPE_UINT32: return read_ae<uint32_t>();
      case SERIALIZE_TYPE_UINT16: return read_ae<uint16_t>();
      case SERIALIZE_TYPE_UINT8:  return read_ae<uint8_t>();
      case SERIALIZE_TYPE_DUOBLE: return read_ae<double>();
      case SERIALIZE_TYPE_BOOL:   return read_ae<bool>();
      case SERIALIZE_TYPE_STRING: return read_ae<std::string>();
      case SERIALIZE_TYPE_OBJECT: return read_ae<section>();
      case SERIALIZE_TYPE_ARRAY:  return read_ae<array_entry>();
      default:
        LOG_ERROR_AND_THROW_UNLESS
          (
           false
           , "unknown entry_type code = "
           + std::to_string(type)
           );
        return {};
      }
    }

    size_t throwable_buffer_reader::read_varint()
    {
      RECURSION_LIMITATION();
      LOG_ERROR_AND_THROW_UNLESS(m_count >= 1, "empty buff, expected place for varint");
      size_t v = 0;
      uint8_t size_mask = (*(uint8_t*)m_ptr) &PORTABLE_RAW_SIZE_MARK_MASK;
      switch (size_mask)
      {
      case PORTABLE_RAW_SIZE_MARK_BYTE: v = read<uint8_t>();break;
      case PORTABLE_RAW_SIZE_MARK_WORD: v = read<uint16_t>();break;
      case PORTABLE_RAW_SIZE_MARK_DWORD: v = read<uint32_t>();break;
      case PORTABLE_RAW_SIZE_MARK_INT64: v = read<uint64_t>();break;
      default:
        LOG_ERROR_AND_THROW_UNLESS
          (
           false
           , "unknown varint size_mask = "
           + std::to_string(size_mask)
           );
      }
      v >>= 2;
      return v;
    }

    storage_entry throwable_buffer_reader::load_storage_entry()
    {
      RECURSION_LIMITATION();
      uint8_t ent_type = 0;
      read(ent_type);
      if(ent_type&SERIALIZE_FLAG_ARRAY)
        return load_storage_array_entry(ent_type);

      switch(ent_type)
      {
      case SERIALIZE_TYPE_INT64:  return read_se<int64_t>();
      case SERIALIZE_TYPE_INT32:  return read_se<int32_t>();
      case SERIALIZE_TYPE_INT16:  return read_se<int16_t>();
      case SERIALIZE_TYPE_INT8:   return read_se<int8_t>();
      case SERIALIZE_TYPE_UINT64: return read_se<uint64_t>();
      case SERIALIZE_TYPE_UINT32: return read_se<uint32_t>();
      case SERIALIZE_TYPE_UINT16: return read_se<uint16_t>();
      case SERIALIZE_TYPE_UINT8:  return read_se<uint8_t>();
      case SERIALIZE_TYPE_DUOBLE: return read_se<double>();
      case SERIALIZE_TYPE_BOOL:   return read_se<bool>();
      case SERIALIZE_TYPE_STRING: return read_se<std::string>();
      case SERIALIZE_TYPE_OBJECT: return read_se<section>();
      case SERIALIZE_TYPE_ARRAY:  return read_se<array_entry>();
      default:
        LOG_ERROR_AND_THROW_UNLESS
          (
           false
           , "unknown entry_type code = "
           + std::to_string(ent_type)
           );
        return {};
      }
    }

    void throwable_buffer_reader::read(section& sec)
    {
      RECURSION_LIMITATION();
      sec.m_entries.clear();
      size_t count = read_varint();
      LOG_ERROR_AND_THROW_UNLESS(count <= max_fields - m_fields, "Too many object fields");
      m_fields += count;
      while(count--)
      {
        //read section name string
        std::string sec_name;
        read_sec_name(sec_name);
        const auto insert_loc = sec.m_entries.lower_bound(sec_name);
        LOG_ERROR_AND_THROW_UNLESS
          (
           insert_loc == sec.m_entries.end()
           || insert_loc->first != sec_name
           , "duplicate key: "
           + sec_name
           );
        sec.m_entries.emplace_hint(insert_loc, std::move(sec_name), load_storage_entry());
      }
    }

    void throwable_buffer_reader::read(std::string& str)
    {
      RECURSION_LIMITATION();
      size_t len = read_varint();
      LOG_ERROR_AND_THROW_UNLESS
        (
         len < MAX_STRING_LEN_POSSIBLE
         , "to big string len value in storage: "
         + std::to_string(len)
         );
      LOG_ERROR_AND_THROW_UNLESS
        (
         m_count >= len
         , "string len count value "
         + std::to_string(len)
         + " goes out of remain storage len "
         + std::to_string(m_count)
         );
      //do this manually to avoid double memory write in huge strings (first time at resize, second at read)
      str.assign((const char*)m_ptr, len);
      m_ptr+=len;
      m_count -= len;
    }

    void throwable_buffer_reader::read(array_entry &ae)
    {
      RECURSION_LIMITATION();
      LOG_ERROR_AND_THROW_UNLESS(false, "Reading array entry is not supported");
    }

    void throwable_buffer_reader::set_limits(size_t objects, size_t fields, size_t strings)
    {
      max_objects = objects;
      max_fields = fields;
      max_strings = strings;
    }

    template<>
    storage_entry throwable_buffer_reader::read_se<std::string>()
    {
      RECURSION_LIMITATION();
      LOG_ERROR_AND_THROW_UNLESS(m_strings + 1 <= max_strings, "Too many strings");
      m_strings += 1;
      return storage_entry(read<std::string>());
    }

    template<>
    storage_entry throwable_buffer_reader::read_se<section>()
    {
      RECURSION_LIMITATION();
      LOG_ERROR_AND_THROW_UNLESS(m_objects < max_objects, "Too many objects");
      ++m_objects;
      section s;//use extra variable due to vs bug, line "storage_entry se(section()); " can't be compiled in visual studio
      storage_entry se(std::move(s));
      section& section_entry = boost::get<section>(se);
      read(section_entry);
      return se;
    }

    template<>
    storage_entry throwable_buffer_reader::read_se<array_entry>()
    {
      RECURSION_LIMITATION();
      uint8_t ent_type = 0;
      read(ent_type);
      LOG_ERROR_AND_THROW_UNLESS(ent_type&SERIALIZE_FLAG_ARRAY, "wrong type sequenses");
      return load_storage_array_entry(ent_type);
    }
  }
}
