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


#ifndef _STRING_CODING_H_
#define _STRING_CODING_H_

#include <string>

namespace epee
{
namespace string_encoding
{
	inline std::string convert_to_ansii(const std::wstring& str_from)
	{
		
		std::string res(str_from.begin(), str_from.end());
		return res;
		/*
		std::string result;
		std::locale loc;
		for(unsigned int i= 0; i < str_from.size(); ++i)
		{
			result += std::use_facet<std::ctype<wchar_t> >(loc).narrow(str_from[i]);
		}
		return result;
		*/
		
		//return boost::lexical_cast<std::string>(str_from);
		/*
		std::string str_trgt;
		if(!str_from.size())
			return str_trgt;
		int cb = ::WideCharToMultiByte( code_page, 0, str_from.data(), (__int32)str_from.size(), 0, 0, 0, 0  );
		if(!cb)
			return str_trgt;
		str_trgt.resize(cb);
		::WideCharToMultiByte(  code_page, 0, str_from.data(), (int)str_from.size(), 
			                        (char*)str_trgt.data(), (int)str_trgt.size(), 0, 0);
		return str_trgt;*/
	}

	inline std::string convert_to_ansii(const std::string& str_from)
	{
		return str_from;
	}

	inline std::wstring convert_to_unicode(const std::string& str_from)
	{
		std::wstring result;
		std::locale loc;
		for(unsigned int i= 0; i < str_from.size(); ++i)
		{
			result += std::use_facet<std::ctype<wchar_t> >(loc).widen(str_from[i]);
		}
		return result;
		
		//return boost::lexical_cast<std::wstring>(str_from);
		/*
		std::wstring str_trgt;
		if(!str_from.size())
			return str_trgt;

		int cb = ::MultiByteToWideChar( code_page, 0, str_from.data(), (int)str_from.size(), 0, 0 );
		if(!cb)
			return str_trgt;

		str_trgt.resize(cb);
		::MultiByteToWideChar( code_page, 0, str_from.data(),(int)str_from.size(), 
								(wchar_t*)str_trgt.data(),(int)str_trgt.size());
		return str_trgt;*/
	}
	inline std::wstring convert_to_unicode(const std::wstring& str_from)
	{
		return str_from;
	}

	template<class target_string>
	inline target_string convert_to_t(const std::wstring& str_from);
	
	template<>
	inline std::string convert_to_t<std::string>(const std::wstring& str_from)
	{
		return convert_to_ansii(str_from);
	}

	template<>
	inline std::wstring convert_to_t<std::wstring>(const std::wstring& str_from)
	{
		return str_from;
	}

	template<class target_string>
	inline target_string convert_to_t(const std::string& str_from);

	template<>
	inline std::string convert_to_t<std::string>(const std::string& str_from)
	{
		return str_from;
	}

	template<>
	inline std::wstring convert_to_t<std::wstring>(const std::string& str_from)
	{
		return convert_to_unicode(str_from);
	}


}
}

#endif //_STRING_CODING_H_
