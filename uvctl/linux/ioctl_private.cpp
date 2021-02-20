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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <iostream>
#include <ioctl_private.h>
#include <log.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int uvctl_ioctl_open()
{
    return open("/dev/" BUILDER_NAME, O_RDWR);
}

int64_t uvctl_write_ioctl(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    if ((fd = uvctl_ioctl_open()) < 0) {
        throw std::runtime_error("failed to open to the builder driver");
    }
}

ioctl_private::~ioctl_private()
{
    close(fd);
}

void ioctl_private::call_ioctl_create_vm(create_vm_args &args)
{
    if (uvctl_write_ioctl(fd, IOCTL_CREATE_VM, &args) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_VM");
    }
}

void ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (uvctl_write_ioctl(fd, IOCTL_DESTROY_VM, &domainid) < 0) {
        log_msg("[ERROR] ioctl failed: IOCTL_DESTROY_VM\n");
    }
}
