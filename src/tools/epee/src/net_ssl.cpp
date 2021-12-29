// Copyright (c) 2018, The Monero Project
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

#include "tools/epee/include/net/net_helper.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/lambda/lambda.hpp>




// openssl genrsa -out /tmp/KEY 4096
// openssl req -new -key /tmp/KEY -out /tmp/REQ
// openssl x509 -req -days 999999 -sha256 -in /tmp/REQ -signkey /tmp/KEY -out /tmp/CERT

namespace
{
  struct openssl_bio_free
  {
    void operator()(BIO* ptr) const noexcept
    {
      BIO_free(ptr);
    }
  };
  using openssl_bio = std::unique_ptr<BIO, openssl_bio_free>;

  struct openssl_pkey_free
  {
    void operator()(EVP_PKEY* ptr) const noexcept
    {
      EVP_PKEY_free(ptr);
    }
  };
  using openssl_pkey = std::unique_ptr<EVP_PKEY, openssl_pkey_free>;

  struct openssl_rsa_free
  {
    void operator()(RSA* ptr) const noexcept
    {
      RSA_free(ptr);
    }
  };
  using openssl_rsa = std::unique_ptr<RSA, openssl_rsa_free>;

  struct openssl_bignum_free
  {
    void operator()(BIGNUM* ptr) const noexcept
    {
      BN_free(ptr);
    }
  };
  using openssl_bignum = std::unique_ptr<BIGNUM, openssl_bignum_free>;

  struct openssl_ec_key_free
  {
    void operator()(EC_KEY* ptr) const noexcept
    {
      EC_KEY_free(ptr);
    }
  };
  using openssl_ec_key = std::unique_ptr<EC_KEY, openssl_ec_key_free>;

  struct openssl_group_free
  {
    void operator()(EC_GROUP* ptr) const noexcept
    {
      EC_GROUP_free(ptr);
    }
  };
  using openssl_group = std::unique_ptr<EC_GROUP, openssl_group_free>;

  boost::system::error_code load_ca_file(boost::asio::ssl::context& ctx, const std::string& path)
  {
    SSL_CTX* const ssl_ctx = ctx.native_handle(); // could be moved from context
    if (ssl_ctx == nullptr)
      return {boost::asio::error::invalid_argument};

    if (!SSL_CTX_load_verify_locations(ssl_ctx, path.c_str(), nullptr))
    {
      return boost::system::error_code{
        int(::ERR_get_error()), boost::asio::error::get_ssl_category()
      };
    }
    return boost::system::error_code{};
  }
}

namespace epee
{
namespace net_utils
{


// https://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
bool create_rsa_ssl_certificate(EVP_PKEY *&pkey, X509 *&cert)
{
  LOG_INFO("Generating SSL certificate");
  pkey = EVP_PKEY_new();
  if (!pkey)
  {
    LOG_ERROR("Failed to create new private key");
    return false;
  }

  openssl_pkey pkey_deleter{pkey};
  openssl_rsa rsa{RSA_new()};
  if (!rsa)
  {
    LOG_ERROR("Error allocating RSA private key");
    return false;
  }

  openssl_bignum exponent{BN_new()};
  if (!exponent)
  {
    LOG_ERROR("Error allocating exponent");
    return false;
  }

  BN_set_word(exponent.get(), RSA_F4);

  if (RSA_generate_key_ex(rsa.get(), 4096, exponent.get(), nullptr) != 1)
  {
    LOG_ERROR("Error generating RSA private key");
    return false;
  }

  if (EVP_PKEY_assign_RSA(pkey, rsa.get()) <= 0)
  {
    LOG_ERROR("Error assigning RSA private key");
    return false;
  }

  // the RSA key is now managed by the EVP_PKEY structure
  (void)rsa.release();

  cert = X509_new();
  if (!cert)
  {
    LOG_ERROR("Failed to create new X509 certificate");
    return false;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 182); // half a year
  if (!X509_set_pubkey(cert, pkey))
  {
    LOG_ERROR("Error setting pubkey on certificate");
    X509_free(cert);
    return false;
  }
  X509_NAME *name = X509_get_subject_name(cert);
  X509_set_issuer_name(cert, name);

  if (X509_sign(cert, pkey, EVP_sha256()) == 0)
  {
    LOG_ERROR("Error signing certificate");
    X509_free(cert);
    return false;
  }
  (void)pkey_deleter.release();
  return true;
}

bool create_ec_ssl_certificate(EVP_PKEY *&pkey, X509 *&cert, int type)
{
  LOG_INFO("Generating SSL certificate");
  pkey = EVP_PKEY_new();
  if (!pkey)
  {
    LOG_ERROR("Failed to create new private key");
    return false;
  }

  openssl_pkey pkey_deleter{pkey};
  openssl_ec_key ec_key{EC_KEY_new()};
  if (!ec_key)
  {
    LOG_ERROR("Error allocating EC private key");
    return false;
  }

  EC_GROUP *group = EC_GROUP_new_by_curve_name(type);
  if (!group)
  {
    LOG_ERROR("Error getting EC group " << type);
    return false;
  }
  openssl_group group_deleter{group};

  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);
  EC_GROUP_set_point_conversion_form(group, POINT_CONVERSION_UNCOMPRESSED);

  if (!EC_GROUP_check(group, NULL))
  {
    LOG_ERROR("Group failed check: " << ERR_reason_error_string(ERR_get_error()));
    return false;
  }
  if (EC_KEY_set_group(ec_key.get(), group) != 1)
  {
    LOG_ERROR("Error setting EC group");
    return false;
  }
  if (EC_KEY_generate_key(ec_key.get()) != 1)
  {
    LOG_ERROR("Error generating EC private key");
    return false;
  }
  if (EVP_PKEY_assign_EC_KEY(pkey, ec_key.get()) <= 0)
  {
    LOG_ERROR("Error assigning EC private key");
    return false;
  }

  // the key is now managed by the EVP_PKEY structure
  (void)ec_key.release();

  cert = X509_new();
  if (!cert)
  {
    LOG_ERROR("Failed to create new X509 certificate");
    return false;
  }
  ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
  X509_gmtime_adj(X509_get_notBefore(cert), 0);
  X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 182); // half a year
  if (!X509_set_pubkey(cert, pkey))
  {
    LOG_ERROR("Error setting pubkey on certificate");
    X509_free(cert);
    return false;
  }
  X509_NAME *name = X509_get_subject_name(cert);
  X509_set_issuer_name(cert, name);

  if (X509_sign(cert, pkey, EVP_sha256()) == 0)
  {
    LOG_ERROR("Error signing certificate");
    X509_free(cert);
    return false;
  }
  (void)pkey_deleter.release();
  return true;
}

ssl_options_t::ssl_options_t(std::vector<std::vector<std::uint8_t>> fingerprints, std::string ca_path)
  : fingerprints_(std::move(fingerprints)),
    ca_path(std::move(ca_path)),
    auth(),
    support(ssl_support_t::e_ssl_support_disabled),
    verification(ssl_verification_t::user_certificates)
{
  std::sort(fingerprints_.begin(), fingerprints_.end());
}


void ssl_authentication_t::use_ssl_certificate(boost::asio::ssl::context &ssl_context) const
{
  ssl_context.use_private_key_file(private_key_path, boost::asio::ssl::context::pem);
  ssl_context.use_certificate_chain_file(certificate_path);
}

bool is_ssl(const unsigned char *data, size_t len)
{
  if (len < get_ssl_magic_size())
    return false;

  // https://security.stackexchange.com/questions/34780/checking-client-hello-for-https-classification
  LOG_DEBUG("SSL detection buffer, " << len << " bytes: "
    << (unsigned)(unsigned char)data[0] << " " << (unsigned)(unsigned char)data[1] << " "
    << (unsigned)(unsigned char)data[2] << " " << (unsigned)(unsigned char)data[3] << " "
    << (unsigned)(unsigned char)data[4] << " " << (unsigned)(unsigned char)data[5] << " "
    << (unsigned)(unsigned char)data[6] << " " << (unsigned)(unsigned char)data[7] << " "
    << (unsigned)(unsigned char)data[8]);
  if (data[0] == 0x16) // record
  if (data[1] == 3) // major version
  if (data[5] == 1) // ClientHello
  if (data[6] == 0 && data[3]*256 + data[4] == data[7]*256 + data[8] + 4) // length check
    return true;
  return false;
}

bool ssl_support_from_string(ssl_support_t &ssl, std::string_view s)
{
  if (s == "disabled")
    ssl = epee::net_utils::ssl_support_t::e_ssl_support_disabled;
  else
    return false;
  return true;
}

} // namespace
} // namespace
