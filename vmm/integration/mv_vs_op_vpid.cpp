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

#include <integration_utils.hpp>
#include <mv_constants.hpp>
#include <mv_hypercall_impl.hpp>
#include <mv_hypercall_t.hpp>
#include <mv_types.hpp>

#include <bsl/convert.hpp>
#include <bsl/enable_color.hpp>
#include <bsl/exit_code.hpp>
#include <bsl/safe_idx.hpp>
#include <bsl/safe_integral.hpp>

namespace hypercall
{
    /// <!-- description -->
    ///   @brief Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    /// <!-- inputs/outputs -->
    ///   @return Always returns bsl::exit_success. If a failure occurs,
    ///     this function will exit early.
    ///
    [[nodiscard]] constexpr auto
    tests() noexcept -> bsl::exit_code
    {
        bsl::safe_u16 mut_id{};
        mv_status_t mut_ret{};
        integration::initialize_globals();

        // invalid VPID
        mut_ret = mv_vs_op_vpid_impl(hndl.get(), MV_INVALID_ID.get(), mut_id.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VPID out of range
        auto const oor{bsl::to_u16(HYPERVISOR_MAX_VPS + bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_vpid_impl(hndl.get(), oor.get(), mut_id.data());
        integration::verify(mut_ret != MV_STATUS_SUCCESS);

        // VPID not yet created
        auto const nyc{bsl::to_u16(HYPERVISOR_MAX_VPS - bsl::safe_u64::magic_1()).checked()};
        mut_ret = mv_vs_op_vpid_impl(hndl.get(), nyc.get(), mut_id.data());
        integration::verify(mut_ret == MV_STATUS_SUCCESS);
        integration::verify(mut_id == MV_INVALID_ID);

        // Self ID should be the current VP
        {
            auto const assigned_vmid{mut_hvc.mv_vs_op_vpid(hypercall::MV_SELF_ID)};
            integration::verify(assigned_vmid.is_valid_and_checked());
            integration::verify(assigned_vmid == mut_hvc.mv_vp_op_vpid());
        }

        // Create VP and verify assignment
        {
            auto const vmid1{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid2{mut_hvc.mv_vm_op_create_vm()};
            auto const vmid3{mut_hvc.mv_vm_op_create_vm()};

            auto const vm1_vpid0{mut_hvc.mv_vp_op_create_vp(vmid1)};
            auto const vm1_vpid1{mut_hvc.mv_vp_op_create_vp(vmid2)};
            auto const vm1_vpid2{mut_hvc.mv_vp_op_create_vp(vmid3)};

            integration::verify(vm1_vpid0.is_valid_and_checked());
            integration::verify(vm1_vpid1.is_valid_and_checked());
            integration::verify(vm1_vpid2.is_valid_and_checked());

            auto const vm1_vp0_vsid1{mut_hvc.mv_vs_op_create_vs(vm1_vpid0)};
            auto const vm1_vp1_vsid2{mut_hvc.mv_vs_op_create_vs(vm1_vpid1)};
            auto const vm1_vp2_vsid3{mut_hvc.mv_vs_op_create_vs(vm1_vpid2)};

            integration::verify(vm1_vp0_vsid1.is_valid_and_checked());
            integration::verify(vm1_vp1_vsid2.is_valid_and_checked());
            integration::verify(vm1_vp2_vsid3.is_valid_and_checked());

            auto const assigned_vm1_vpid0{mut_hvc.mv_vs_op_vpid(vm1_vp0_vsid1)};
            auto const assigned_vm1_vpid1{mut_hvc.mv_vs_op_vpid(vm1_vp1_vsid2)};
            auto const assigned_vm1_vpid2{mut_hvc.mv_vs_op_vpid(vm1_vp2_vsid3)};

            integration::verify(assigned_vm1_vpid0 == vm1_vpid0);
            integration::verify(assigned_vm1_vpid1 == vm1_vpid1);
            integration::verify(assigned_vm1_vpid2 == vm1_vpid2);

            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vm1_vp2_vsid3));
            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vm1_vp1_vsid2));
            integration::verify(mut_hvc.mv_vs_op_destroy_vs(vm1_vp0_vsid1));

            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vm1_vpid2));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vm1_vpid1));
            integration::verify(mut_hvc.mv_vp_op_destroy_vp(vm1_vpid0));

            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid3));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid2));
            integration::verify(mut_hvc.mv_vm_op_destroy_vm(vmid1));
        }

        constexpr auto num_loops{0x1000_umx};
        for (bsl::safe_idx mut_i{}; mut_i < num_loops; ++mut_i) {
            auto const assigned_vpid{mut_hvc.mv_vs_op_vpid(hypercall::MV_SELF_ID)};
            integration::verify(assigned_vpid.is_valid_and_checked());
            integration::verify(bsl::to_umx(assigned_vpid) < HYPERVISOR_MAX_VPS);
        }

        return bsl::exit_success;
    }
}

/// <!-- description -->
///   @brief Provides the main entry point for this application.
///
/// <!-- inputs/outputs -->
///   @return bsl::exit_success on success, bsl::exit_failure otherwise.
///
[[nodiscard]] auto
main() noexcept -> bsl::exit_code
{
    bsl::enable_color();
    return hypercall::tests();
}
