/// @copyright
/// Copyright (C) 2020 Assured Information Security, Inc.
///
/// @copyright
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// @copyright
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// @copyright
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#ifndef MV_TRANSLATION_T_HPP
#define MV_TRANSLATION_T_HPP

#include <mv_constants.hpp>

#include <bsl/debug.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/safe_integral.hpp>
#include <bsl/unlikely.hpp>
#include <bsl/unlikely_assert.hpp>

namespace hypercall
{
    class mv_translation_t final
    {

    // return {{}, gla, (gpa_and_flags & gpa_mask), (gpa_and_flags & fgs_mask), true};
    public:
        const bsl::safe_uint64 vaddr;
        const bsl::safe_uint64 laddr;
        const bsl::safe_uint64 paddr;
        const bsl::safe_uint64 flags;
        const bool is_valid; 
    };
    
}

#endif
