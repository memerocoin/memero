// Copyright (c) 2021, The Lolnero Project
// Copyright (c) 2014-2020, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

template <class Archive, class T>
struct serializer{
  static bool serialize(Archive &ar, T &v) {
    return serialize(ar, v, typename std::is_integral<T>::type(), typename is_blob_type<T>::type(), typename is_basic_type<T>::type());
  }
  template<typename A>
  static bool serialize(Archive &ar, T &v, std::false_type, std::true_type, A a) {
    ar.serialize_blob(&v, sizeof(v));
    return true;
  }
  template<typename A>
  static bool serialize(Archive &ar, T &v, std::true_type, std::false_type, A a) {
    ar.serialize_int(v);
    return true;
  }
  static bool serialize(Archive &ar, T &v, std::false_type, std::false_type, std::false_type) {
    //serialize_custom(ar, v, typename has_free_serializer<T>::type());
    return v.do_serialize(ar);
  }
  static bool serialize(Archive &ar, T &v, std::false_type, std::false_type, std::true_type) {
    //serialize_custom(ar, v, typename has_free_serializer<T>::type());
    return do_serialize(ar, v);
  }
};

template <class Archive, class T>
bool do_serialize(Archive &ar, T &v)
{
  return ::serializer<Archive, T>::serialize(ar, v);
}
template <class Archive>
bool do_serialize(Archive &ar, bool &v)
{
  ar.serialize_blob(&v, sizeof(v));
  return true;
}

namespace serialization {
  /*! \namespace detail
   *
   * \brief declaration and default definition for the functions used the API
   *
   */
  namespace detail
  {
    template <typename T>
    void prepare_custom_vector_serialization(size_t size, std::vector<T>& vec, const std::false_type& /*is_saving*/)
    {
      vec.resize(size);
    }

    template <typename T>
    void prepare_custom_deque_serialization(size_t size, std::deque<T>& vec, const std::false_type& /*is_saving*/)
    {
      vec.resize(size);
    }

    /*! \fn do_check_stream_state
     *
     * \brief self explanatory
     */
    template<class Stream>
    bool do_check_stream_state(Stream& s, std::true_type, bool noeof)
    {
      return s.good();
    }
    /*! \fn do_check_stream_state
     *
     * \brief self explanatory
     *
     * \detailed Also checks to make sure that the stream is not at EOF
     */
    template<class Stream>
    bool do_check_stream_state(Stream& s, std::false_type, bool noeof)
    {
      bool result = false;
      if (s.good())
        {
          std::ios_base::iostate state = s.rdstate();
          result = noeof || EOF == s.peek();
          s.clear(state);
        }
      return result;
    }
  }

  /*! \fn check_stream_state
   *
   * \brief calls detail::do_check_stream_state for ar
   */
  template<class Archive>
  bool check_stream_state(Archive& ar, bool noeof = false)
  {
    return detail::do_check_stream_state(ar.stream(), typename Archive::is_saving(), noeof);
  }

  /*! \fn serialize
   *
   * \brief serializes \a v into \a ar
   */
  template <class Archive, class T>
  bool serialize(Archive &ar, T &v)
  {
    bool r = do_serialize(ar, v);
    return r && check_stream_state(ar, false);
  }

  /*! \fn serialize
   *
   * \brief serializes \a v into \a ar
   */
  template <class Archive, class T>
  bool serialize_noeof(Archive &ar, T &v)
  {
    bool r = do_serialize(ar, v);
    return r && check_stream_state(ar, true);
  }
}
