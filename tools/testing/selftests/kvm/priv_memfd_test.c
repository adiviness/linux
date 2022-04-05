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

#define PRIV_MEM_GPA		0xb0000000
#define PRIV_MEM_SIZE		0x2000
#define PRIV_MEM_END		(PRIV_MEM_GPA + PRIV_MEM_SIZE)

#define SHARED_MEM_DATA_BYTE	0x66
#define PRIV_MEM_DATA_BYTE	0x99

#define PRIV_MEM_SLOT		10

#define VCPU_ID			0

#define VM_STAGE_PROCESSED(x)	pr_info("Processed stage %s\n", #x)

typedef bool (*vm_stage_handler_fn)(struct kvm_vm *,
				void *, uint64_t);
typedef void (*guest_code_fn)(void);
struct test_run_helper {
	char *test_desc;
	vm_stage_handler_fn vmst_handler;
	guest_code_fn guest_fn;
	void *shared_mem;
	int priv_memfd;
};

static bool verify_byte_pattern(void *mem, uint8_t byte, uint32_t size)
{
	uint8_t *buf = (uint8_t *)mem;

	for (uint32_t i = 0; i < size; i++) {
		if (buf[i] != byte)
			return false;
	}

	return true;
}

/* Test to verify guest private accesses on private memory with following steps:
 * 1) guest signals vmm that it has started upon guest code entry
 * 2) vmm populates the shared memory with known pattern and continues guest
 *	execution
 * 3) guest writes a different pattern on the private memory and signals vmm
 *      that it has updated private memory
 * 4) vmm verifies its shared memory contents to be same as the data populated
 *      in step 2 and continues guest execution
 * 5) guest verifies its private memory contents to be same as the data
 *      populated in step 3 and marks the end of the guest execution
 */
#define PMPAT_ID				0
#define PMPAT_DESC				"PrivateMemoryPrivateAccessTest"

/* Guest code exection stages for private mem access test */
#define PMPAT_GUEST_STARTED			0ULL
#define PMPAT_GUEST_PRIV_MEM_UPDATED		1ULL

static bool pmpat_handle_vm_stage(struct kvm_vm *vm,
			void *test_info,
			uint64_t stage)
{
	void *shared_mem = ((struct test_run_helper *)test_info)->shared_mem;

	switch (stage) {
	case PMPAT_GUEST_STARTED: {
		/* Initialize the contents of shared memory */
		memset(shared_mem, SHARED_MEM_DATA_BYTE, PRIV_MEM_SIZE);
		VM_STAGE_PROCESSED(PMPAT_GUEST_STARTED);
		break;
	}
	case PMPAT_GUEST_PRIV_MEM_UPDATED: {
		/* verify host updated data is still intact */
		TEST_ASSERT(verify_byte_pattern(shared_mem,
			SHARED_MEM_DATA_BYTE, PRIV_MEM_SIZE),
			"Shared memory view mismatch");
		VM_STAGE_PROCESSED(PMPAT_GUEST_PRIV_MEM_UPDATED);
		break;
	}
	default:
		printf("Unhandled VM stage %ld\n", stage);
		return false;
	}

	return true;
}

static void pmpat_guest_code(void)
{
	void *priv_mem = (void *)PRIV_MEM_GPA;

	GUEST_SYNC(PMPAT_GUEST_STARTED);

	memset(priv_mem, PRIV_MEM_DATA_BYTE, PRIV_MEM_SIZE);
	GUEST_SYNC(PMPAT_GUEST_PRIV_MEM_UPDATED);

	GUEST_ASSERT(verify_byte_pattern(priv_mem,
			PRIV_MEM_DATA_BYTE, PRIV_MEM_SIZE));

	GUEST_DONE();
}

static struct test_run_helper priv_memfd_testsuite[] = {
	[PMPAT_ID] = {
		.test_desc = PMPAT_DESC,
		.vmst_handler = pmpat_handle_vm_stage,
		.guest_fn = pmpat_guest_code,
	},
};

static void vcpu_work(struct kvm_vm *vm, uint32_t test_id)
{
	struct kvm_run *run;
	struct ucall uc;
	uint64_t cmd;

	/*
	 * Loop until the guest is done.
	 */
	run = vcpu_state(vm, VCPU_ID);

	while (1) {
		vcpu_run(vm, VCPU_ID);

		if (run->exit_reason == KVM_EXIT_IO) {
			cmd = get_ucall(vm, VCPU_ID, &uc);
			if (cmd != UCALL_SYNC)
				break;

			if (!priv_memfd_testsuite[test_id].vmst_handler(
				vm, &priv_memfd_testsuite[test_id], uc.args[1]))
				break;

			continue;
		}

		if (run->exit_reason == KVM_EXIT_HYPERCALL) {
			uint64_t gpa, npages, attrs;
			int priv_memfd =
				priv_memfd_testsuite[test_id].priv_memfd;
			int ret;
			int fallocate_mode;

			if (run->hypercall.nr != KVM_HC_MAP_GPA_RANGE) {
				printf("Unhandled Hypercall %lld\n",
							run->hypercall.nr);
				break;
			}

			gpa = run->hypercall.args[0];
			npages = run->hypercall.args[1];
			attrs = run->hypercall.args[2];

			if ((gpa >= PRIV_MEM_GPA) && ((gpa +
				(npages << MIN_PAGE_SHIFT)) <= PRIV_MEM_END)) {
				printf("Unhandled gpa 0x%lx npages %ld\n",
					gpa, npages);
				break;
			}

			if (attrs & KVM_MAP_GPA_RANGE_ENCRYPTED)
				fallocate_mode = 0;
			else {
				fallocate_mode = (FALLOC_FL_PUNCH_HOLE |
					FALLOC_FL_KEEP_SIZE);
			}
			pr_info("Converting off 0x%lx pages 0x%lx to %s\n",
				(gpa - PRIV_MEM_GPA), npages,
				fallocate_mode ?
					"shared" : "private");
			ret = fallocate(priv_memfd, fallocate_mode,
				(gpa - PRIV_MEM_GPA),
				npages << MIN_PAGE_SHIFT);
			TEST_ASSERT(ret != -1,
				"fallocate failed in hc handling");
			run->hypercall.ret = 0;
			continue;
		}

		if (run->exit_reason == KVM_EXIT_MEMORY_ERROR) {
			uint64_t gpa, size, flags;
			int ret;
			int priv_memfd =
				priv_memfd_testsuite[test_id].priv_memfd;
			int fallocate_mode;

			gpa = run->memory.gpa;
			size = run->memory.size;
			flags = run->memory.flags;

			if ((gpa < PRIV_MEM_GPA) || ((gpa + size)
							> PRIV_MEM_END)) {
				printf("Unhandled gpa 0x%lx size 0x%lx\n",
					gpa, size);
				break;
			}

			if (flags & KVM_MEMORY_EXIT_FLAG_PRIVATE)
				fallocate_mode = 0;
			else {
				fallocate_mode = (FALLOC_FL_PUNCH_HOLE |
						FALLOC_FL_KEEP_SIZE);
			}
			pr_info("Converting off 0x%lx size 0x%lx to %s\n",
				(gpa - PRIV_MEM_GPA), size,
				fallocate_mode ?
					"shared" : "private");
			ret = fallocate(priv_memfd, fallocate_mode,
				(gpa - PRIV_MEM_GPA), size);
			TEST_ASSERT(ret != -1,
				"fallocate failed in memory error handling");
			continue;
		}

		printf("Unhandled VCPU exit reason %d\n", run->exit_reason);
		break;
	}

	if (run->exit_reason == KVM_EXIT_IO && cmd == UCALL_ABORT)
		TEST_FAIL("%s at %s:%ld, val = %lu", (const char *)uc.args[0],
			  __FILE__, uc.args[1], uc.args[2]);
}

static int priv_memory_region_add(struct kvm_vm *vm, void *mem, uint32_t slot,
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

	return ret;
}

/* Do private access to the guest's private memory */
static void setup_and_execute_test(uint32_t test_id)
{
	struct kvm_vm *vm;
	int priv_memfd = -1;
	int ret;
	void *shared_mem;
	struct kvm_priv_mem_info priv_mem_info, rd_priv_mem_info;

	vm = vm_create_default(VCPU_ID, 0,
				priv_memfd_testsuite[test_id].guest_fn);

	/* Allocate shared memory */
	shared_mem = mmap(NULL, PRIV_MEM_SIZE,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	/* Allocate private memory */
	priv_memfd = memfd_create("vm_private_mem", MFD_INACCESSIBLE);
	TEST_ASSERT(priv_memfd != -1, "Failed to create priv_memfd");
	ret = fallocate(priv_memfd, 0, 0, PRIV_MEM_SIZE);
	TEST_ASSERT(ret != -1, "fallocate failed");

	ret = priv_memory_region_add(vm, shared_mem,
				     PRIV_MEM_SLOT, PRIV_MEM_SIZE,
				     PRIV_MEM_GPA, priv_memfd, 0);
	TEST_ASSERT(ret == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed,\n"
			" rc: %i errno: %i slot: %i\n",
			ret, errno, PRIV_MEM_SLOT);

	pr_info("Mapping guest private pages 0x%x page_size 0x%x\n",
					PRIV_MEM_SIZE/vm_get_page_size(vm),
					vm_get_page_size(vm));
	virt_map(vm, PRIV_MEM_GPA, PRIV_MEM_GPA,
					(PRIV_MEM_SIZE/vm_get_page_size(vm)));

	/* Mark all accesses from vcpu as private accesses */
	priv_mem_info.start = PRIV_MEM_GPA;
	priv_mem_info.size = PRIV_MEM_SIZE;
	ret = ioctl(vcpu_get_fd(vm, VCPU_ID), KVM_SET_PRIVATE_GPA_RANGE,
		&priv_mem_info);
	TEST_ASSERT(ret == 0, "VCPU ioctl to set private memory failed!\n");
	ret = ioctl(vcpu_get_fd(vm, VCPU_ID), KVM_GET_PRIVATE_GPA_RANGE,
		&rd_priv_mem_info);
	TEST_ASSERT(ret == 0, "VCPU ioctl to get private memory failed!\n");
	pr_info("priv_mem_start 0x%llx size 0x%llx\n", rd_priv_mem_info.start,
					rd_priv_mem_info.size);
	priv_memfd_testsuite[test_id].shared_mem = shared_mem;
	priv_memfd_testsuite[test_id].priv_memfd = priv_memfd;
	vcpu_work(vm, test_id);

	munmap(shared_mem, PRIV_MEM_SIZE);
	priv_memfd_testsuite[test_id].shared_mem = NULL;
	close(priv_memfd);
	priv_memfd_testsuite[test_id].priv_memfd = -1;
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	for (uint32_t i = 0; i < ARRAY_SIZE(priv_memfd_testsuite); i++) {
		pr_info("Running test %s\n", priv_memfd_testsuite[i].test_desc);
		setup_and_execute_test(i);
		pr_info("completed test %s\n",
				priv_memfd_testsuite[i].test_desc);
	}

	return 0;
}
