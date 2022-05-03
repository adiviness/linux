
// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)

#define _4KB_PAGE_SIZE 0x1000
#define _2MB_PAGE_SIZE ((_4KB_PAGE_SIZE * 1024 / 2))

#define MEM_SIZE _2MB_PAGE_SIZE
//#define MEM_SIZE _4KB_PAGE_SIZE
#define DATA_BYTE	0x99

#define VCPU_ID			0
#define TEST_MEM_SLOT		10
#define TEST_MEM_GPA		0xb0000000

void guest_func() {
	int ret;
	/* Mark the GPA range to be treated as always accessed privately */
	ret = kvm_hypercall(KVM_HC_MAP_GPA_RANGE, TEST_MEM_GPA,
		MEM_SIZE >> MIN_PAGE_SHIFT,
		KVM_MARK_GPA_RANGE_ENC_ACCESS, 0);
	GUEST_ASSERT_1(ret == 0, ret);

	volatile char* mem = (char*)TEST_MEM_GPA;
	for (size_t i = 0; i < MEM_SIZE; ++i) {
		mem[i] = DATA_BYTE;
	}

	/*
	void* mem = (void*)TEST_MEM_GPA;
	memset(mem, DATA_BYTE, MEM_SIZE);
	*/
	GUEST_DONE();
}

static void priv_memory_region_add(struct kvm_vm *vm, void *mem, uint32_t slot,
				uint32_t size, uint64_t guest_addr,
				uint32_t priv_fd, uint64_t priv_offset)
{
	struct kvm_userspace_memory_region_ext region_ext;
	int ret;

	region_ext.region.slot = slot;
	region_ext.region.flags = KVM_MEM_PRIVATE;
	region_ext.region.guest_phys_addr = guest_addr;
	region_ext.region.memory_size = size;
	region_ext.region.userspace_addr = (uintptr_t) mem;
	region_ext.private_fd = priv_fd;
	region_ext.private_offset = priv_offset;
	ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION, &region_ext);
	TEST_ASSERT(ret == 0, "Failed to register user region for gpa 0x%lx\n",
		guest_addr);
}

int main() {
	int ret;

	struct kvm_vm* vm = vm_create_default(VCPU_ID, 0, guest_func);

	// huge pages for shared memory
	const int mmap_flags = MAP_PRIVATE |
		MAP_ANONYMOUS |
		MAP_NORESERVE |
		MAP_HUGETLB |
		MAP_HUGE_2MB;
	// normal pages for private memory
	const unsigned int memfd_flags = MFD_INACCESSIBLE;


	/* Allocate shared memory */
	void* shared_mem = mmap(NULL,
							MEM_SIZE,
							PROT_READ | PROT_WRITE,
							mmap_flags,
							-1,
							0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	/* Allocate private memory */
	const int priv_memfd = memfd_create("vm_private_mem", memfd_flags);
	TEST_ASSERT(priv_memfd != -1, "Failed to create priv_memfd");
	ret = fallocate(priv_memfd, 0, 0, MEM_SIZE);
	TEST_ASSERT(ret != -1, "fallocate failed");

	priv_memory_region_add(vm,
						   shared_mem,
						   TEST_MEM_SLOT,
						   MEM_SIZE,
					       TEST_MEM_GPA,
						   priv_memfd,
						   0);

	virt_map(vm,
			 TEST_MEM_GPA,
			 TEST_MEM_GPA,
			 (MEM_SIZE/vm_get_page_size(vm)));

	struct kvm_run* run = vcpu_state(vm, VCPU_ID);
	run->exit_reason = 0;
	vcpu_run(vm, VCPU_ID);
	printf("exit reason: %d\n", run->exit_reason);

	munmap(shared_mem, MEM_SIZE);
	close(priv_memfd);
	kvm_vm_free(vm);

	return 0;
}
