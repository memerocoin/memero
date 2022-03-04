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

#include "enableable.h"
#include "keyvalue_serialization_overloads.h"

#include <type_traits>
#include <boost/utility/value_init.hpp>





namespace epee
{
  /************************************************************************/
  /* Serialize map declarations                                           */
  /************************************************************************/
#define BEGIN_KV_SERIALIZE_MAP() \
public: \
  template<class t_storage> \
  bool store( t_storage& st, typename t_storage::hsection hparent_section = nullptr) const\
  {\
    using type = typename std::remove_const<typename std::remove_reference<decltype(*this)>::type>::type; \
    auto &self = const_cast<type&>(*this); \
    return self.template serialize_map<true>(st, hparent_section); \
  }\
  template<class t_storage> \
  bool _load( t_storage& stg, typename t_storage::hsection hparent_section = nullptr)\
  {\
    return serialize_map<false>(stg, hparent_section);\
  }\
  template<class t_storage> \
  bool load( t_storage& stg, typename t_storage::hsection hparent_section = nullptr)\
  {\
    try{\
    return serialize_map<false>(stg, hparent_section);\
    }\
    catch(const std::exception& err) \
    { \
      (void)(err); \
      LOG_ERROR("Exception on unserializing: " + std::string(err.what())); \
      return false; \
    }\
  }\
  /*template<typename T> T& this_type_resolver() { return *this; }*/ \
  /*using this_type = std::result_of<decltype(this_type_resolver)>::type;*/ \
  template<bool is_store, class t_storage> \
  bool serialize_map(t_storage& stg, typename t_storage::hsection hparent_section) \
  {

#define KV_SERIALIZE_N(varialble, val_name) \
  epee::serialization::selector<is_store>::serialize(this->varialble, stg, hparent_section, val_name);

#define KV_SERIALIZE_PARENT(type) \
  do { \
    if (!((type*)this)->serialize_map<is_store, t_storage>(stg, hparent_section)) \
      return false; \
  } while(0);

  template<typename T> inline void serialize_default(const T &t, T v) { }
  template<typename T> inline void serialize_default(T &t, T v) { t = v; }

#define KV_SERIALIZE_OPT_N(variable, val_name, default_value) \
  do { \
    if (is_store && this->variable == default_value) \
      break; \
    if (!epee::serialization::selector<is_store>::serialize(this->variable, stg, hparent_section, val_name)) \
      epee::serialize_default(this->variable, default_value); \
  } while (0);

#define KV_SERIALIZE_VAL_POD_AS_BLOB_N(varialble, val_name) \
  static_assert(std::is_standard_layout<decltype(this->varialble)>::value, "t_type must be a standard layout type."); \
  static_assert(std::is_trivial<decltype(this->varialble)>::value, "t_type must be a trivial type."); \
  epee::serialization::selector<is_store>::serialize_t_val_as_blob(this->varialble, stg, hparent_section, val_name);

#define KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(varialble, val_name) \
  epee::serialization::selector<is_store>::serialize_stl_container_pod_val_as_blob(this->varialble, stg, hparent_section, val_name);

#define END_KV_SERIALIZE_MAP() return true;}

#define KV_SERIALIZE(varialble)                           KV_SERIALIZE_N(varialble, #varialble)
#define KV_SERIALIZE_VAL_POD_AS_BLOB(varialble)           KV_SERIALIZE_VAL_POD_AS_BLOB_N(varialble, #varialble)
#define KV_SERIALIZE_CONTAINER_POD_AS_BLOB(varialble)     KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(varialble, #varialble)
#define KV_SERIALIZE_OPT(variable,default_value)          KV_SERIALIZE_OPT_N(variable, #variable, default_value)

}




