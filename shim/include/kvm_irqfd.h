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

#ifndef KVM_IRQFD_H
#define KVM_IRQFD_H

#include <stdint.h>

#ifdef __clang__
#pragma clang diagnostic ignored "-Wold-style-cast"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

/** @brief defines the padding size */
#define PAD_SIZE_IRQFD ((uint32_t)16)

    /**
     * @struct kvm_irqfd
     *
     * <!-- description -->
     *   @brief Allows setting an eventfd to directly trigger a guest interrupt..
     */
    struct kvm_irqfd
    {
        /** @brief specifies the file descriptor to use as the eventfd */
        uint32_t fd;
        /** @brief specifies the irqchip pin toggled by this event*/
        uint32_t gsi;
        /** @brief The flag is used to remove irqfd */
        uint32_t flags;
        /** @brief Additional eventfd the user must pass when KVM_IRQFD_FLAG_RESAMPLE is set */
        uint32_t resamplefd;
        /** @brief TODO*/
        uint8_t pad[PAD_SIZE_IRQFD];
    };

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif
