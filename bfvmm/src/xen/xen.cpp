//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <mutex>
#include <bfgpalayout.h>
#include <compiler.h>

#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/vcpu.h>

#include <xen/evtchn.h>
#include <xen/gnttab.h>
#include <xen/xen.h>

#include <public/arch-x86/cpuid.h>
#include <public/errno.h>
#include <public/memory.h>
#include <public/platform.h>
#include <public/version.h>
#include <public/hvm/hvm_op.h>
#include <public/hvm/params.h>

#define XEN_MAJOR 4UL
#define XEN_MINOR 13UL

using wrmsr_handler = bfvmm::intel_x64::wrmsr_handler;

namespace microv {

static std::mutex xen_mutex;
static uint32_t xen_domid = 0;
static uint32_t xen_vcpuid = 0;
static uint32_t xen_apicid = 0;
static uint32_t xen_acpiid = 0;

static constexpr auto hcall_page_msr = 0xC0000500;
static constexpr auto xen_leaf_base = 0x40000100;
static constexpr auto xen_leaf(int i) { return xen_leaf_base + i; }

static void make_xen_ids(xen_domain *dom, xen *xen)
{
    if (dom->initdom()) {
        xen->domid = 0;
        xen->vcpuid = 0;
        xen->apicid = 0;
        xen->acpiid = 0;
        return;
    } else {
        std::lock_guard<std::mutex> lock(xen_mutex);
        xen->domid = ++xen_domid;
        xen->vcpuid = ++xen_vcpuid;
        xen->apicid = ++xen_apicid;
        xen->acpiid = ++xen_acpiid;
    }
}

static bool handle_exception(base_vcpu *vcpu)
{
    namespace int_info = vmcs_n::vm_exit_interruption_information;

    auto info = int_info::get();
    auto type = int_info::interruption_type::get(info);

    if (type == int_info::interruption_type::non_maskable_interrupt) {
        return false;
    }

    auto vec = int_info::vector::get(info);
    bfdebug_info(0, "Guest exception");
    bfdebug_subnhex(0, "vector", vec);
    bfdebug_subnhex(0, "rip", vcpu->rip());

    auto rip = vcpu->map_gva_4k<uint8_t>(vcpu->rip(), 32);
    auto buf = rip.get();

    printf("        - bytes: ");
    for (auto i = 0; i < 32; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    vmcs_n::exception_bitmap::set(0);

    return true;
}

static bool xen_leaf0(base_vcpu *vcpu)
{
    vcpu->set_rax(xen_leaf(5));
    vcpu->set_rbx(XEN_CPUID_SIGNATURE_EBX);
    vcpu->set_rcx(XEN_CPUID_SIGNATURE_ECX);
    vcpu->set_rdx(XEN_CPUID_SIGNATURE_EDX);

    vcpu->advance();
    return true;
}

static bool xen_leaf1(base_vcpu *vcpu)
{
    vcpu->set_rax(0x00040D00);
    vcpu->set_rbx(0);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

static bool xen_leaf2(base_vcpu *vcpu)
{
    vcpu->set_rax(1);
    vcpu->set_rbx(hcall_page_msr);
    vcpu->set_rcx(0);
    vcpu->set_rdx(0);

    vcpu->advance();
    return true;
}

void xen::queue_virq(uint32_t virq)
{
    m_evtchn->queue_virq(virq);
}

bool xen::xen_leaf4(base_vcpu *vcpu)
{
    uint32_t rax = 0;

//  rax |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;
    rax |= XEN_HVM_CPUID_X2APIC_VIRT;
//  rax |= XEN_HVM_CPUID_IOMMU_MAPPINGS;
    rax |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
    rax |= XEN_HVM_CPUID_DOMID_PRESENT;

    vcpu->set_rax(rax);

    /* These ID values are *not* the same as the microv ones */
    vcpu->set_rbx(this->vcpuid);
    vcpu->set_rcx(this->domid);

    vcpu->advance();
    return true;
}

static bool wrmsr_hcall_page(base_vcpu *vcpu, wrmsr_handler::info_t &info)
{
    auto map = vcpu->map_gpa_4k<uint8_t>(info.val);
    auto buf = gsl::span(map.get(), 0x1000);

    for (uint8_t i = 0; i < 55; i++) {
        auto entry = buf.subspan(i * 32, 32);

        entry[0] = 0xB8U;
        entry[1] = i;
        entry[2] = 0U;
        entry[3] = 0U;
        entry[4] = 0U;
        entry[5] = 0x0FU;
        entry[6] = 0x01U;
        entry[7] = 0xC1U;
        entry[8] = 0xC3U;
    }

    return true;
}

bool xen::handle_hypercall(xen_vcpu *vcpu)
{
    switch (vcpu->rax()) {
    case __HYPERVISOR_memory_op:
        return this->handle_memory_op();
    case __HYPERVISOR_xen_version:
        return this->handle_xen_version();
    case __HYPERVISOR_hvm_op:
        return this->handle_hvm_op();
    case __HYPERVISOR_event_channel_op:
        return this->handle_event_channel_op();
    case __HYPERVISOR_grant_table_op:
        return this->handle_grant_table_op();
    case __HYPERVISOR_platform_op:
        return this->handle_platform_op();
    case __HYPERVISOR_console_io:
        return this->handle_console_io();
    default:
        return false;
    }
}

bool xen::handle_console_io()
{
    expects(m_dom->initdom());

    uint64_t len = m_vcpu->rsi();
    auto buf = m_vcpu->map_gva_4k<char>(m_vcpu->rdx(), len);

    switch (m_vcpu->rdi()) {
    case CONSOLEIO_read: {
        auto n = m_dom->hvc_rx_get(gsl::span(buf.get(), len));
        m_vcpu->set_rax(n);
        return true;
    }
    case CONSOLEIO_write: {
        auto n = m_dom->hvc_tx_put(gsl::span(buf.get(), len));
        m_vcpu->set_rax(n);
        return true;
    }
    default:
        return false;
    }
}

bool xen::handle_memory_op()
{
    switch (m_vcpu->rdi()) {
    case XENMEM_memory_map:
        try {
            auto map = m_vcpu->map_arg<xen_memory_map_t>(m_vcpu->rsi());
            if (map->nr_entries < m_vcpu->dom()->e820().size()) {
                throw std::runtime_error("guest E820 too small");
            }

            auto addr = map->buffer.p;
            auto size = map->nr_entries;

            auto e820 = m_vcpu->map_gva_4k<e820_entry_t>(addr, size);
            auto e820_view = gsl::span<e820_entry_t>(e820.get(), size);

            map->nr_entries = 0;

            for (const auto &entry : m_vcpu->dom()->e820()) {
                e820_view[map->nr_entries].addr = entry.addr;
                e820_view[map->nr_entries].size = entry.size;
                e820_view[map->nr_entries].type = entry.type;

                // Any holes in our E820 will use the default MTRR type UC
                //m_mtrr.emplace_back(mtrr_range(entry));

                map->nr_entries++;
            }

            m_vcpu->set_rax(0);
            return true;
        } catchall({
            ;
        })
        break;
    case XENMEM_add_to_physmap:
        try {
            auto xatp = m_vcpu->map_arg<xen_add_to_physmap_t>(m_vcpu->rsi());
            if (xatp->domid != DOMID_SELF) {
                m_vcpu->set_rax(-EINVAL);
            }

            switch (xatp->space) {
            case XENMAPSPACE_gmfn_foreign:
                m_vcpu->set_rax(-ENOSYS);
                return true;
            case XENMAPSPACE_shared_info:
                m_shinfo = m_vcpu->map_gpa_4k<shared_info>(xatp->gpfn << 12);
                m_vcpu->set_rax(0);
                return true;
            case XENMAPSPACE_grant_table:
                m_gnttab->mapspace_grant_table(xatp.get());
                m_vcpu->set_rax(0);
                return true;
            default:
                return false;
            }

        } catchall({
            ;
        })
        break;
    case XENMEM_decrease_reservation:
        try {
            auto arg = m_vcpu->map_arg<xen_memory_reservation_t>(m_vcpu->rsi());

            expects(arg->domid == DOMID_SELF);
            expects(arg->extent_order == 0);

            auto gva = arg->extent_start.p;
            auto len = arg->nr_extents * sizeof(xen_pfn_t);
            auto map = m_vcpu->map_gva_4k<xen_pfn_t>(gva, len);
            auto gfn = map.get();

            for (auto i = 0U; i < arg->nr_extents; i++) {
                auto dom = m_vcpu->dom();
                auto gpa = (gfn[i] << 12);
                dom->unmap(gpa);
                dom->release(gpa);
            }

            m_vcpu->set_rax(arg->nr_extents);
            return true;
        } catchall({
            m_vcpu->set_rax(FAILURE);
        })
    default:
        break;
    }

    return false;
}

bool xen::handle_xen_version()
{
    switch (m_vcpu->rdi()) {
    case XENVER_version: return m_xenver->version();
    case XENVER_extraversion: return m_xenver->extraversion();
    case XENVER_compile_info: return m_xenver->compile_info();
    case XENVER_capabilities: return m_xenver->capabilities();
    case XENVER_changeset: return m_xenver->changeset();
    case XENVER_platform_parameters: return m_xenver->platform_parameters();
    case XENVER_get_features: return m_xenver->get_features();
    case XENVER_pagesize: return m_xenver->pagesize();
    case XENVER_guest_handle: return m_xenver->guest_handle();
    case XENVER_commandline: return m_xenver->commandline();
    case XENVER_build_id: return m_xenver->build_id();
    default: return false;
    }
}

static bool valid_cb_via(uint64_t via)
{
    const auto type = (via & HVM_PARAM_CALLBACK_IRQ_TYPE_MASK) >> 56;
    if (type != HVM_PARAM_CALLBACK_TYPE_VECTOR) {
        return false;
    }

    const auto vector = via & 0xFFU;
    if (vector < 0x20U || vector > 0xFFU) {
        return false;
    }

    return true;
}

bool xen::handle_hvm_op()
{
    switch (m_vcpu->rdi()) {
    case HVMOP_set_param:
        try {
            auto arg = m_vcpu->map_arg<xen_hvm_param_t>(m_vcpu->rsi());
            switch (arg->index) {
            case HVM_PARAM_CALLBACK_IRQ:
                if (valid_cb_via(arg->value)) {
                    m_evtchn->set_callback_via(arg->value & 0xFF);
                    m_vcpu->set_rax(0);
                } else {
                    m_vcpu->set_rax(-EINVAL);
                }
                return true;
            default:
                bfalert_info(0, "Unsupported HVM set_param");
                return false;
            }
        } catchall({
            return false;
        })
    //case HVMOP_get_param:
    //    try {
    //        auto arg = m_vcpu->map_arg<xen_hvm_param_t>(m_vcpu->rsi());
    //        switch (arg->index) {
    //        case HVM_PARAM_CONSOLE_EVTCHN:
    //            arg->value = m_evtchn->bind_console();
    //            break;
    //        case HVM_PARAM_CONSOLE_PFN:
    //            m_console = m_vcpu->map_gpa_4k<uint8_t>(PVH_CONSOLE_GPA);
    //            arg->value = PVH_CONSOLE_GPA >> 12;
    //            break;
    //        case HVM_PARAM_STORE_EVTCHN:
    //            arg->value = m_evtchn->bind_store();
    //            m_vcpu->set_rax(-ENOSYS);
    //            return true;
    //            break;
    //        case HVM_PARAM_STORE_PFN:
    //            m_store = m_vcpu->map_gpa_4k<uint8_t>(PVH_STORE_GPA);
    //            arg->value = PVH_STORE_GPA >> 12;
    //            m_vcpu->set_rax(-ENOSYS);
    //            return true;
    //            break;
    //        default:
    //            bfalert_nhex(0, "Unsupported HVM get_param:", arg->index);
    //            return false;
    //        }

    //        m_vcpu->set_rax(0);
    //        return true;
    //    } catchall({
    //        return false;
    //    })
    case HVMOP_pagetable_dying:
        m_vcpu->set_rax(0);
        return true;
    default:
       return false;
    }
}

bool xen::handle_event_channel_op()
{
    switch (m_vcpu->rdi()) {
    case EVTCHNOP_init_control:
    {
        auto ctl = m_vcpu->map_arg<evtchn_init_control_t>(m_vcpu->rsi());
        m_evtchn->init_control(ctl.get());
        m_vcpu->set_rax(0);
        return true;
    }
    case EVTCHNOP_alloc_unbound:
    {
        auto eau = m_vcpu->map_arg<evtchn_alloc_unbound_t>(m_vcpu->rsi());
        m_evtchn->alloc_unbound(eau.get());
        m_vcpu->set_rax(0);
        return true;
    }
    case EVTCHNOP_expand_array:
    {
        auto arg = m_vcpu->map_arg<evtchn_expand_array_t>(m_vcpu->rsi());
        m_evtchn->expand_array(arg.get());
        m_vcpu->set_rax(0);
        return true;
    }
    case EVTCHNOP_bind_virq:
    {
        auto arg = m_vcpu->map_arg<evtchn_bind_virq_t>(m_vcpu->rsi());
        m_evtchn->bind_virq(arg.get());
        m_vcpu->set_rax(0);
        return true;
    }
    case EVTCHNOP_send:
    {
        auto arg = m_vcpu->map_arg<evtchn_send_t>(m_vcpu->rsi());
        m_evtchn->send(arg.get());
        m_vcpu->set_rax(0);
        return true;
    }
    default:
        ;
    }

    return false;
}

bool xen::handle_grant_table_op()
{
    switch (m_vcpu->rdi()) {
    case GNTTABOP_query_size:
        try {
            auto arg = m_vcpu->map_arg<gnttab_query_size_t>(m_vcpu->rsi());
            m_gnttab->query_size(arg.get());
            m_vcpu->set_rax(0);
            return true;
        } catchall({
            ;
        })
    case GNTTABOP_set_version:
        try {
            auto arg = m_vcpu->map_arg<gnttab_set_version_t>(m_vcpu->rsi());
            m_gnttab->set_version(arg.get());
            m_vcpu->set_rax(SUCCESS);
            return true;
        } catchall ({
            ;
        })
    default:
        return false;
    }
}

bool xen::handle_platform_op()
{
    expects(m_dom->initdom());
    auto xpf = m_vcpu->map_arg<xen_platform_op_t>(m_vcpu->rdi());

    switch (xpf->cmd) {
    case XENPF_get_cpuinfo:
    {
        struct xenpf_pcpuinfo info = xpf->u.pcpu_info;

        info.max_present = 1;
        info.flags = XEN_PCPU_FLAGS_ONLINE;
        info.apic_id = this->apicid;
        info.acpi_id = this->acpiid;

        m_vcpu->set_rax(0);
        return true;
    }
    default:
        ;
    }

    return false;
}

xen::xen(xen_vcpu *vcpu, xen_domain *dom) :
    m_vcpu{vcpu},
    m_dom{dom},
    m_evtchn{std::make_unique<class evtchn>(vcpu)},
    m_gnttab{std::make_unique<class gnttab>(vcpu)},
    m_xenver{std::make_unique<class xenver>(vcpu)}
{
    make_xen_ids(dom, this);

    vcpu->add_cpuid_emulator(xen_leaf(0), {xen_leaf0});
    vcpu->add_cpuid_emulator(xen_leaf(2), {xen_leaf2});
    vcpu->emulate_wrmsr(hcall_page_msr, {wrmsr_hcall_page});
    vcpu->add_vmcall_handler({&xen::handle_hypercall, this});
    vcpu->add_cpuid_emulator(xen_leaf(1), {xen_leaf1});
    vcpu->add_cpuid_emulator(xen_leaf(4), {&xen::xen_leaf4, this});

    vcpu->add_handler(0, handle_exception);
}

}
