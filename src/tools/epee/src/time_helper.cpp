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


#include "tools/epee/include/time_helper.h"

#include <chrono>  // chrono::system_clock
#include <ctime>   // localtime
#include <sstream> // stringstream
#include <iomanip> // put_time

#include <boost/lexical_cast.hpp>

namespace epee
{
namespace misc_utils
{
  // https://stackoverflow.com/questions/17223096/outputting-date-and-time-in-c-using-stdchrono
	std::string get_internet_time_str(const time_t time_)
	{
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_), "%a, %d %b %Y %H:%M:%S GMT");
    return ss.str();
	}

	std::string get_time_interval_string(const time_t& time_)
	{
		std::string res;
		time_t tail = time_;
		int days = tail/(60*60*24);
		tail = tail%(60*60*24);
		int hours = tail/(60*60);
		tail = tail%(60*60);
		int minutes = tail/(60);
		tail = tail%(60);
		int seconds = tail;
		res = std::string() + "d" + boost::lexical_cast<std::string>(days) + ".h" + boost::lexical_cast<std::string>(hours) + ".m" + boost::lexical_cast<std::string>(minutes) + ".s" + boost::lexical_cast<std::string>(seconds);
		return res;
	}
}
}
