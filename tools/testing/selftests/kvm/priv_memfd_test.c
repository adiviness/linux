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
#include <linux/memfd.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>

#define VCPU_ID 0

#define MEM_REGION_SIZE		0x200000

/*
 * Somewhat arbitrary location, intended to not overlap anything.
 */
#define MEM_REGION_GPA		0xc0000000

#define PRIV_MEM_GPA           0xb0000000
#define PRIV_MEM_SIZE          0x4000

#define PRIV_MEM_SLOT          10

static const uint64_t MMIO_VAL = 0xbeefull;

static void vcpu_worker(struct kvm_vm *vm)
{
	struct kvm_run *run;
	struct ucall uc;
	uint64_t cmd;
        static uint32_t mmio_exit_count = 0;

	/*
	 * Loop until the guest is done.  Re-enter the guest on all MMIO exits.
	 */
	run = vcpu_state(vm, VCPU_ID);

	/* TODO: Handle KVM_EXIT_MEMORY_ERROR */
	while (1) {
		vcpu_run(vm, VCPU_ID);

		printf("VCPU exit reason %d\n", run->exit_reason);
		if (run->exit_reason == KVM_EXIT_IO) {
			cmd = get_ucall(vm, VCPU_ID, &uc);
			if (cmd != UCALL_SYNC)
				break;

			continue;
		}

		if (run->exit_reason != KVM_EXIT_MMIO)
			break;

		TEST_ASSERT(!run->mmio.is_write, "Unexpected exit mmio write");
		TEST_ASSERT(run->mmio.len == 8,
			    "Unexpected exit mmio size = %u", run->mmio.len);

		TEST_ASSERT(run->mmio.phys_addr == MEM_REGION_GPA,
			    "Unexpected exit mmio address = 0x%llx",
			    run->mmio.phys_addr);
		mmio_exit_count++;
		if (mmio_exit_count % 2) {
			printf("Emulated mmio value to be %lx\n", MMIO_VAL);
			memcpy(run->mmio.data, &MMIO_VAL, 8);
		} else {
			printf("Emulated mmio value to be 0\n");
			memset(run->mmio.data, 0, 8);
		}
	}

	if (run->exit_reason == KVM_EXIT_IO && cmd == UCALL_ABORT)
		TEST_FAIL("%s at %s:%ld, val = %lu", (const char *)uc.args[0],
			  __FILE__, uc.args[1], uc.args[2]);
}

static void guest_code(void)
{
	volatile uint64_t val;

	GUEST_SYNC(0);

        /* Random MMIO accesses which may be repurposed later
         * to indicate checkpoints so that userspace vmm can take
         * different actions to support private memfd tests
         */
	val = READ_ONCE(*((volatile uint64_t *)MEM_REGION_GPA));
	GUEST_ASSERT_1(val == MMIO_VAL, val);

	val = READ_ONCE(*((volatile uint64_t *)MEM_REGION_GPA));
	GUEST_ASSERT_1(val == 0, val);

	val = READ_ONCE(*((volatile uint64_t *)MEM_REGION_GPA));
	GUEST_ASSERT_1(val == MMIO_VAL, val);

	val = READ_ONCE(*((volatile uint64_t *)MEM_REGION_GPA));
	GUEST_ASSERT_1(val == 0, val);

	*((volatile uint64_t *)PRIV_MEM_GPA) = 0xdeadbeef;
	val = *((volatile uint64_t *)PRIV_MEM_GPA);
	GUEST_ASSERT_1(val == 0xdeadbeef, val);

	GUEST_DONE();
}

static int priv_memory_region_add(struct kvm_vm *vm, void *mem, uint32_t slot,
				   uint32_t size, uint64_t guest_addr,
				uint64_t priv_offset, uint32_t priv_fd)
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

/* Do shared access to the guest's private memory */
static void test_shared_mem_access(void)
{
	struct kvm_vm *vm;
	int memfd = 0;
	int ret;
	void *mem;
	uint64_t val;
	struct kvm_priv_mem_info priv_mem_info, rd_priv_mem_info;

	vm = vm_create_default(VCPU_ID, 0, guest_code);
	__virt_pg_map(vm, MEM_REGION_GPA, MEM_REGION_GPA, X86_PAGE_SIZE_4K);

        /* Allocate shared memory */
	mem = mmap(NULL, PRIV_MEM_SIZE,
		   PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	TEST_ASSERT(mem != MAP_FAILED, "Failed to mmap() host");

	/* Allocate private memory */
	memfd = memfd_create("vm_private_mem", MFD_INACCESSIBLE);
	TEST_ASSERT(memfd != -1, "Failed to create memfd");

	ret = fallocate(memfd, 0, 0, PRIV_MEM_SIZE);
	TEST_ASSERT(ret != -1, "fallocate failed");

	ret = priv_memory_region_add(vm, mem,
				     PRIV_MEM_SLOT, PRIV_MEM_SIZE,
				     PRIV_MEM_GPA, 0, memfd);
	TEST_ASSERT(ret == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed,\n"
		    "  rc: %i errno: %i slot: %i\n",
		    ret, errno, PRIV_MEM_SLOT);
	memset(mem, 0, vm_get_page_size(vm));

	printf("Mapping guest pages %x page_size %x\n",
					PRIV_MEM_SIZE/vm_get_page_size(vm),
					vm_get_page_size(vm));
	virt_map(vm, PRIV_MEM_GPA, PRIV_MEM_GPA, (PRIV_MEM_SIZE)/vm_get_page_size(vm));

        /* Mark all accesses from vcpu as shared accesses */
	priv_mem_info.start = 0;
	priv_mem_info.size = 0;
	ret = ioctl(vcpu_get_fd(vm, VCPU_ID), KVM_SET_PRIVATE_GFN_RANGE,
		&priv_mem_info);
	TEST_ASSERT(ret == 0, "VCPU ioctl to set private memory failed!\n");
	ret = ioctl(vcpu_get_fd(vm, VCPU_ID), KVM_GET_PRIVATE_GFN_RANGE,
		&rd_priv_mem_info);
	TEST_ASSERT(ret == 0, "VCPU ioctl to get private memory failed!\n");
	printf("priv_mem_start %lld size %lld\n", rd_priv_mem_info.start,
					rd_priv_mem_info.size);
	vcpu_worker(vm);

	/* With shared access to private memory finally
	 * selftests and guests should see the same memory contents
	 */
	val = *((volatile uint64_t *)mem);
	TEST_ASSERT(val == 0xdeadbeef, "value unexpected %lx\n", val);

	munmap(mem, PRIV_MEM_SIZE);
	close(memfd);
	kvm_vm_free(vm);
}

int main(int argc, char *argv[])
{
	uint32_t pa_bits, va_bits;

	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);
        printf("Running the test!\n");

	kvm_get_cpu_address_width(&pa_bits, &va_bits);
	printf("KVM supported PA bits %d VA bits %d\n", pa_bits,
				va_bits);
	test_shared_mem_access();

	return 0;
}
