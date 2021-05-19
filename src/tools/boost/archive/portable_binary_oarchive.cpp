#include "tools/boost/archive/portable_binary_oarchive.hpp"

namespace boost { namespace archive {

void
portable_binary_oarchive::save_impl(
    const boost::intmax_t l,
    const char maxsize
){
    signed char size = 0;

    if(l == 0){
        this->primitive_base_t::save(size);
        return;
    }

    boost::intmax_t ll;
    bool negative = (l < 0);
    if(negative)
        ll = -l;
    else
        ll = l;

    do{
        ll >>= CHAR_BIT;
        ++size;
    }while(ll != 0);

    this->primitive_base_t::save(
        static_cast<signed char>(negative ? -size : size)
    );

    if(negative)
        ll = -l;
    else
        ll = l;
    char * cptr = reinterpret_cast<char *>(& ll);
    #if BOOST_ENDIAN_BIG_BYTE
        cptr += (sizeof(boost::intmax_t) - size);
        if(m_flags & endian_little)
            reverse_bytes(size, cptr);
    #else
        if(m_flags & endian_big)
            reverse_bytes(size, cptr);
    #endif
    this->primitive_base_t::save_binary(cptr, size);
}

void
portable_binary_oarchive::init(unsigned int flags) {
    if(m_flags == (endian_big | endian_little)){
        boost::serialization::throw_exception(
            portable_binary_oarchive_exception()
        );
    }
    if(0 == (flags & boost::archive::no_header)){
        // write signature in an archive version independent manner
        const std::string file_signature(
            boost::archive::BOOST_ARCHIVE_SIGNATURE()
        );
        * this << file_signature;
        // ignore archive version checking
        const boost::archive::library_version_type v{};
        /*
        // write library version
        const boost::archive::library_version_type v(
            boost::archive::BOOST_ARCHIVE_VERSION()
        );
        */
        * this << v;
    }
    save(static_cast<unsigned char>(m_flags >> CHAR_BIT));
}

} }
