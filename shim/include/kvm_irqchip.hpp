/**
 * @copyright
 * Copyright (C) 2020 Assured Information Security, Inc.
 *
 * @copyright
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * @copyright
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * @copyright
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KVM_IRQCHIP_H
#define KVM_IRQCHIP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)


    /**
     * @struct kvm_irqchip
     *
     * <!-- description -->
     *   @brief see /include/uapi/linux/kvm.h in Linux for more details.
     */
    struct kvm_irqchip
    {
        
        int32_t chip_id;  /* 0 = PIC1, 1 = PIC2, 2 = IOAPIC */
	    int32_t pad;
        union {
            /** @brief replace me with contents from KVM API */
		    char dummy[512];  /* reserving space */
	//	    struct kvm_pic_state pic;
	//	    struct kvm_ioapic_state ioapic;
	    } irqchip;
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif


#ifndef KVM_IRQCHIP_HPP
#define KVM_IRQCHIP_HPP

#include <bsl/array.hpp>
#include <bsl/convert.hpp>
#include <bsl/safe_integral.hpp>

#pragma pack(push, 1)

namespace shim
{
    /// @struct kvm_msrs
    ///
    /// <!-- description -->
    ///   @brief see /include/uapi/linux/kvm.h in Linux for more details.
    ///
    struct kvm_irqchip final
    {
        /** @brief irqchip id */
        bsl::uint32 chip_id;
        /** @brief number of pad in entries */
        bsl::uint32 pad;
        /// @brief stores each entry in the RDL
    };

}

#pragma pack(pop)

#endif