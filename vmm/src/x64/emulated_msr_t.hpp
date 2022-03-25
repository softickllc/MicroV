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

#ifndef EMULATED_MSR_T_HPP
#define EMULATED_MSR_T_HPP

#include <bf_syscall_t.hpp>
#include <gs_t.hpp>
#include <intrinsic_t.hpp>
#include <tls_t.hpp>
#include <vs_t.hpp>

#include <bsl/debug.hpp>
#include <bsl/discard.hpp>
#include <bsl/errc_type.hpp>
#include <bsl/unlikely.hpp>

namespace microv
{
    /// <!-- description -->
    ///   @brief See mv_msr_entry_t for more details
    ///
    struct mv_msr_entry_t final //NOLINT[bsl-user-defined-type-names-match-header-name,-warnings-as-errors]
    {
        /// @brief stores the MSR number
        uint64_t msr_num;
        /// @brief stores the MSR value
        uint64_t value;
        /// @brief boolean to say if this value has been set yet
        bool is_set;
    };

     /// @brief stores the MAX_EMULATED_MSRS
    constexpr auto MAX_EMULATED_MSRS{200_idx};

    /// @class microv::emulated_msr_t
    ///
    /// <!-- description -->
    ///   @brief Defines MicroV's emulated MSR handler. Emulated resources
    ///     are owned by guest VSs and provide an emulated interface for
    ///     guest VMs.
    ///
    ///   @note IMPORTANT: This class is a per-VS class, and all accesses
    ///     to CPUID from a VM (root or guest) must come from this class.
    ///
    class emulated_msr_t final
    {
        /// @brief stores the ID of the VS associated with this emulated_msr_t
        bsl::safe_u16 m_assigned_vsid{};

        /// @brief stores the standard CPUID leaves
        bsl::array<mv_msr_entry_t, MAX_EMULATED_MSRS.get()> m_msrs{};

    public:
        /// <!-- description -->
        ///   @brief Initializes this emulated_msr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///   @param vsid the ID of the VS associated with this emulated_msr_t
        ///
        constexpr void
        initialize(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic,
            bsl::safe_u16 const &vsid) noexcept
        {
            bsl::expects(this->assigned_vsid() == syscall::BF_INVALID_ID);

            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            /// NOTE:
            /// - Since the MSR permissions map is a global resource due to
            ///   the limited amount of physically contiguous memory that
            ///   is required, the initialization of the MSR permission maps
            ///   is done in gs_initialize. Any MSR ports that need to be
            ///   trapped, or passed through should be done there.
            ///

            m_assigned_vsid = ~vsid;
        }

        /// <!-- description -->
        ///   @brief Release the emulated_msr_t.
        ///
        /// <!-- inputs/outputs -->
        ///   @param gs the gs_t to use
        ///   @param tls the tls_t to use
        ///   @param sys the bf_syscall_t to use
        ///   @param intrinsic the intrinsic_t to use
        ///
        constexpr void
        release(
            gs_t const &gs,
            tls_t const &tls,
            syscall::bf_syscall_t const &sys,
            intrinsic_t const &intrinsic) noexcept
        {
            bsl::discard(gs);
            bsl::discard(tls);
            bsl::discard(sys);
            bsl::discard(intrinsic);

            m_assigned_vsid = {};
        }

        /// <!-- description -->
        ///   @brief Returns the ID of the PP associated with this
        ///     emulated_msr_t
        ///
        /// <!-- inputs/outputs -->
        ///   @return Returns the ID of the PP associated with this
        ///     emulated_msr_t
        ///
        [[nodiscard]] constexpr auto
        assigned_vsid() const noexcept -> bsl::safe_u16
        {
            bsl::ensures(m_assigned_vsid.is_valid_and_checked());
            return ~m_assigned_vsid;
        }

        /// <!-- description -->
        ///   @brief Get an emulated MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param msr The MSR to get
        ///   @return Returns the value of the emulated MSR. If the MSR isn't
        ///    emulated bsl::safe_u64::failure() is returned instead.
        ///
        [[nodiscard]] constexpr auto
        get(syscall::bf_syscall_t const &sys, bsl::safe_u64 const &msr) const noexcept
            -> bsl::safe_u64
        {
            bsl::discard(sys);
            bsl::discard(msr);
            constexpr auto msr_mtrrcap{0xfe_u32};
            constexpr auto msr_patchlevel{0x8b_u32};
            constexpr auto msr_smttseg{0xC0010112_u32};
            constexpr auto msr_syscfg{0xC0010010_u32};
            constexpr auto msr_idfk{0xC0011029_u32};
            constexpr auto msr_perf_ctl0{0xC0010000_u32};
            constexpr auto msr_perf_ctl1{0xC0010001_u32};
            constexpr auto msr_perf_ctl2{0xC0010002_u32};
            constexpr auto msr_perf_ctl3{0xC0010003_u32};
            constexpr auto msr_perf_ctr0{0xC0010004_u32};
            constexpr auto msr_perf_ctr1{0xC0010005_u32};
            constexpr auto msr_perf_ctr2{0xC0010006_u32};
            constexpr auto msr_perf_ctr3{0xC0010007_u32};
            constexpr auto msr_tsc{0x10_u32};
            constexpr auto msr_machinecheck{0x017b_u32};

            switch (bsl::to_u32_unsafe(msr).get()) {
                case msr_patchlevel.get():
                case msr_tsc.get():
                case msr_mtrrcap.get(): {
                    return sys.bf_intrinsic_op_rdmsr(bsl::to_u32(msr));
                }

                default: {
                    break;
                }
            }

            // See if we already have an entry for this MSR to update
            for (bsl::safe_idx mut_i{}; mut_i < MAX_EMULATED_MSRS.get(); ++mut_i) {
                auto const *const cst_entry{m_msrs.at_if(mut_i)};

                if ((cst_entry->is_set) && (cst_entry->msr_num == msr.get())) { //NOLINT [bsl-boolean-operators-forbidden,-warnings-as-errors]
                    // bsl::debug() << "Found existing index " << bsl::endl;
                    // bsl::debug() << "EMULATED READ MSR " << bsl::hex(msr) << " val=" << bsl::hex(pmut_entry->value) << bsl::endl;
                    return bsl::make_safe(cst_entry->value);
                }
                bsl::touch();
            }

            bsl::debug() << "WARNING: UNHANDLED READ, RETURNING 0: MSR " << bsl::hex(msr)
                         << bsl::endl;
            constexpr auto zero_val{0x0_u64};
            return zero_val;

            // return bsl::safe_u64::failure();
        }

        /// <!-- description -->
        ///   @brief Set an emulated MSR
        ///
        /// <!-- inputs/outputs -->
        ///   @param sys the bf_syscall_t to use
        ///   @param msr The MSR to set
        ///   @param val The value to set the MSR with
        ///   @return Returns bsl::errc_success on success, bsl::errc_failure
        ///     and friends otherwise
        ///
        [[nodiscard]] constexpr auto
        set(syscall::bf_syscall_t const &sys,
            bsl::safe_u64 const &msr,
            bsl::safe_u64 const &val) noexcept -> bsl::errc_type
        {
            bsl::discard(sys);
            bsl::discard(msr);
            bsl::discard(val);

            // bsl::debug() << "EMULATED WRITE MSR " << bsl::hex(msr) << " val=" << bsl::hex(val) << bsl::endl;

            // See if we already have an entry for this MSR to update
            for (bsl::safe_idx mut_i{}; mut_i < MAX_EMULATED_MSRS.get(); ++mut_i){
                auto *const pmut_entry{m_msrs.at_if(mut_i)};

                if ((pmut_entry->is_set) && (pmut_entry->msr_num == msr.get())) { //NOLINT [bsl-boolean-operators-forbidden,-warnings-as-errors]
                    // bsl::debug() << "Found existing index " << bsl::endl;
                    pmut_entry->value = val.get();
                    return bsl::errc_success;
                }
                bsl::touch();
            }

            // Look for a free entry to use
            for (bsl::safe_idx mut_i{}; mut_i < MAX_EMULATED_MSRS.get(); ++mut_i){
                auto *const pmut_entry{m_msrs.at_if(mut_i)};
                // If this entry is already taken, continue
                if (!pmut_entry->is_set) {
                    // bsl::debug() << "Found free index " << bsl::endl;
                    pmut_entry->msr_num = msr.get();
                    pmut_entry->value = val.get();
                    pmut_entry->is_set = true;
                    return bsl::errc_success;
                }
                bsl::touch();
            }

            // UT OH!! Out of entries
            return bsl::errc_failure;
        }
    };
}

#endif