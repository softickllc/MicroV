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

#include <debug.h>
#include <g_mut_hndl.h>
#include <kvm_dtable.h>
#include <kvm_segment.h>
#include <kvm_sregs.h>
#include <mv_constants.h>
#include <mv_hypercall.h>
#include <mv_rdl_t.h>
#include <mv_reg_t.h>
#include <platform.h>
#include <shared_page_for_current_pp.h>
#include <shim_vcpu_t.h>
#include <types.h>

/**
 * <!-- description -->
 *   @brief Set a kvm_segment based on the base, limit, selector and attrib
 *     registers given by MicroV.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_seg the kvm_segment to set
 *   @param base the base register
 *   @param limit the limit register
 *   @param selector the selector register
 *   @param attrib the attrib register
 */
static void
set_kvm_segment(
    struct kvm_segment *const pmut_seg,
    uint64_t const base,
    uint64_t const limit,
    uint64_t const selector,
    uint64_t const attrib) NOEXCEPT
{
    pmut_seg->selector = (uint16_t)selector;
    pmut_seg->limit = (uint32_t)limit;
    pmut_seg->base = base;

    pmut_seg->type = (uint8_t)((attrib & ATTRIB_TYPE_MASK) >> ATTRIB_TYPE_SHIFT);
    pmut_seg->present = (uint8_t)((attrib & ATTRIB_PRESENT_MASK) >> ATTRIB_PRESENT_SHIFT);
    pmut_seg->dpl = (uint8_t)((attrib & ATTRIB_DPL_MASK) >> ATTRIB_DPL_SHIFT);
    pmut_seg->db = (uint8_t)((attrib & ATTRIB_DB_MASK) >> ATTRIB_DB_SHIFT);
    pmut_seg->l = (uint8_t)((attrib & ATTRIB_L_MASK) >> ATTRIB_L_SHIFT);
    pmut_seg->g = (uint8_t)((attrib & ATTRIB_G_MASK) >> ATTRIB_G_SHIFT);
    pmut_seg->avl = (uint8_t)((attrib & ATTRIB_AVL_MASK) >> ATTRIB_AVL_SHIFT);
    pmut_seg->s = (uint8_t)((attrib & ATTRIB_S_MASK) >> ATTRIB_S_SHIFT);
}

/**
 * <!-- description -->
 *   @brief Handles the execution of kvm_get_sregs.
 *
 * <!-- inputs/outputs -->
 *   @param pmut_mut_vcpu arguments received from private data
 *   @param pmut_args the arguments provided by userspace
 *   @return SHIM_SUCCESS on success, SHIM_FAILURE on failure.
 */
NODISCARD int64_t
handle_vcpu_kvm_get_sregs(
    struct shim_vcpu_t *pmut_mut_vcpu, struct kvm_sregs *const pmut_args) NOEXCEPT
{
    struct mv_rdl_t *pmut_rdl;
    struct mv_rdl_entry_t *mut_e;

    unsigned long mut_i;
    const int mv_regs[] = {
        // clang-format off
        mv_reg_t_es_base,   mv_reg_t_es_limit,   mv_reg_t_es_selector,   mv_reg_t_es_attrib,
        mv_reg_t_cs_base,   mv_reg_t_cs_limit,   mv_reg_t_cs_selector,   mv_reg_t_cs_attrib,
        mv_reg_t_ss_base,   mv_reg_t_ss_limit,   mv_reg_t_ss_selector,   mv_reg_t_ss_attrib,
        mv_reg_t_ds_base,   mv_reg_t_ds_limit,   mv_reg_t_ds_selector,   mv_reg_t_ds_attrib,
        mv_reg_t_fs_base,   mv_reg_t_fs_limit,   mv_reg_t_fs_selector,   mv_reg_t_fs_attrib,
        mv_reg_t_gs_base,   mv_reg_t_gs_limit,   mv_reg_t_gs_selector,   mv_reg_t_gs_attrib,
        mv_reg_t_ldtr_base, mv_reg_t_ldtr_limit, mv_reg_t_ldtr_selector, mv_reg_t_ldtr_attrib,
        mv_reg_t_tr_base,   mv_reg_t_tr_limit,   mv_reg_t_tr_selector,   mv_reg_t_tr_attrib,
        mv_reg_t_gdtr_base, mv_reg_t_gdtr_limit,
        mv_reg_t_idtr_base, mv_reg_t_idtr_limit,
        mv_reg_t_cr0,
        mv_reg_t_cr2,
        mv_reg_t_cr3,
        mv_reg_t_cr4,
        mv_reg_t_cr8
        // clang-format on
    };
    const uint64_t mv_regs_size = (uint64_t)(sizeof(mv_regs) / sizeof(mv_regs[0]));
    struct kvm_segment *const kvm_segs[] = {
        &pmut_args->es,
        &pmut_args->cs,
        &pmut_args->ss,
        &pmut_args->ds,
        &pmut_args->fs,
        &pmut_args->gs,
        &pmut_args->ldt,
        &pmut_args->tr,
    };
    const uint64_t kvm_seg_size = (uint64_t)(sizeof(kvm_segs) / sizeof(uintptr_t));

    platform_expects(NULL != pmut_mut_vcpu);
    platform_expects(NULL != pmut_args);
    platform_expects(MV_INVALID_HANDLE != g_mut_hndl);

    pmut_rdl = (struct mv_rdl_t *)shared_page_for_current_pp();
    platform_expects(NULL != pmut_rdl);
    mut_e = pmut_rdl->entries;

    for (mut_i = 0UL; (uint64_t)mut_i < mv_regs_size; ++mut_i) {
        mut_e[mut_i].reg = (uint64_t)mv_regs[mut_i];
        mut_e[mut_i].val = (uint64_t)0;
    }

    pmut_rdl->num_entries = (uint64_t)mut_i;

    if (mv_vs_op_reg_get_list(g_mut_hndl, pmut_mut_vcpu->vsid)) {
        bferror("mv_vs_op_reg_get_list failed");
        return SHIM_FAILURE;
    }

    /// NOTE:
    /// - The code bellow is position dependent. Any line with mut_i must not be
    ///   shifted around.
    ///

    for (mut_i = 0UL; (uint64_t)mut_i < kvm_seg_size; mut_i += 4UL) {
        /// NOTE:
        /// - If the ABI could garantie that MicroV won't change the order of
        ///   entries in mv_rdl_t after a call to mv_vs_op_reg_get_list, we
        ///   shouldn't need to check that reg is at the correct offset,
        ///   otherwise we would need to check, e.g. with:
        ///
        /// platform_expects(
        ///     mut_e[mut_i + 0UL].reg == mv_regs[mut_i + 0UL] &&
        ///     mut_e[mut_i + 1UL].reg == mv_regs[mut_i + 1UL] &&
        ///     mut_e[mut_i + 2UL].reg == mv_regs[mut_i + 2UL] &&
        ///     mut_e[mut_i + 3UL].reg == mv_regs[mut_i + 3UL]
        /// );
        set_kvm_segment(
            kvm_segs[mut_i],
            mut_e[mut_i + 0UL].val,
            mut_e[mut_i + 1UL].val,
            mut_e[mut_i + 2UL].val,
            mut_e[mut_i + 3UL].val);
    }

    pmut_args->gdt.limit = (uint16_t)mut_e[++mut_i].val;
    pmut_args->gdt.base = mut_e[++mut_i].val;

    pmut_args->idt.limit = (uint16_t)mut_e[++mut_i].val;
    pmut_args->idt.base = mut_e[++mut_i].val;

    pmut_args->cr0 = mut_e[++mut_i].val;
    pmut_args->cr2 = mut_e[++mut_i].val;
    pmut_args->cr3 = mut_e[++mut_i].val;
    pmut_args->cr4 = mut_e[++mut_i].val;
    pmut_args->cr8 = mut_e[++mut_i].val;

    // --

    /// NOTE:
    /// - We need to add to the spec the efer and the apic base msr before
    ///   uncommenting the section bellow.
    ///

#if 0
    mut_i = 0UL;
    mut_e[mut_i].reg = (uint64_t)mv_msr_t_efer;
    mut_e[++mut_i].reg = (uint64_t)mv_msr_t_apic_base;
    pmut_rdl->num_entries = (uint64_t)(mut_i + 1UL);

    if (mv_vs_op_msr_get_list(g_mut_hndl, pmut_mut_vcpu->vsid)) {
        bferror("ms_vs_op_msr_get_list failed");
        return SHIM_FAILURE;
    }

    mut_i = 0UL;
    pmut_args->efer = mut_e[mut_i].val;
    pmut_args->apic_base = mut_e[++mut_i].val;
#endif

    /// TODO:
    /// - The kvm_sregs struct has an interrupt_bitmap field that we need to set
    ///

    return SHIM_SUCCESS;
}
