
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

#define VCPU_ID			0
#define PRIV_MEM_SLOT		10
#define PRIV_MEM_GPA		0xb0000000
#define PRIV_MEM_SIZE 0x2000

// mmap huge page specifiers
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)


// page sizes
#define PAGE_SIZE 0x1000
#define _2MB_PAGE_SIZE ((PAGE_SIZE * 1024 / 2))
#define _1GB_PAGE_SIZE 0x40000000

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

char* page_size_to_str(const unsigned int val) {
	switch (val) {
	case X86_PAGE_SIZE_4K:
		return "X86_PAGE_SIZE_4K";
	case X86_PAGE_SIZE_2M:
		return "X86_PAGE_SIZE_2M";
	case X86_PAGE_SIZE_1G:
		return "X86_PAGE_SIZE_1G";
	default:
		return "UNKNOWN";
	}
}

static void guest_func(void) {
	GUEST_DONE();
}

unsigned int pick_page_type(char* arg) {
	if (arg[0] == '1') {
		return X86_PAGE_SIZE_4K;
	}
	else if (arg[0] == '2') {
		return X86_PAGE_SIZE_2M;
	}
	else if (arg[0] == '3') {
		return X86_PAGE_SIZE_1G;
	}
	else {
		return X86_PAGE_SIZE_4K;
	}
}

int main(int argc, char *argv[])
{
	int ret;
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	if (argc < 2) {
		printf("need page type arg\n");
		exit(1);
	}
	const unsigned int page_type = pick_page_type(argv[1]);

	printf("using page size %s\n", page_size_to_str(page_type));

	// setup vm
	struct kvm_vm* vm = vm_create_default(VCPU_ID, 0, &guest_func);
	int priv_memfd = -1;

	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	size_t mem_size = PRIV_MEM_SIZE;
	unsigned int memfd_flags = MFD_INACCESSIBLE;
	if (page_type == X86_PAGE_SIZE_2M) {
		mmap_flags |= (MAP_HUGETLB | MAP_HUGE_2MB);
		memfd_flags |= (MFD_HUGETLB | MFD_HUGE_2MB);
		mem_size = _2MB_PAGE_SIZE;
	}
	else if (page_type == X86_PAGE_SIZE_1G) {
		mmap_flags |= (MAP_HUGETLB | MAP_HUGE_1GB);
		memfd_flags |= (MFD_HUGETLB | MFD_HUGE_1GB);
		mem_size = _1GB_PAGE_SIZE;
	}

	printf("mem size: %x\n", mem_size);

	void* shared_mem = mmap(NULL,
							mem_size,
							PROT_READ | PROT_WRITE,
							mmap_flags, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	/* Allocate private memory */
	priv_memfd = memfd_create("blah_vm_private_mem", memfd_flags);
	TEST_ASSERT(priv_memfd != -1, "Failed to create priv_memfd");
	ret = fallocate(priv_memfd, 0, 0, mem_size);
	TEST_ASSERT(ret != -1, "fallocate failed");

	ret = priv_memory_region_add(vm, shared_mem,
				     PRIV_MEM_SLOT, mem_size,
				     PRIV_MEM_GPA, priv_memfd, 0);
	TEST_ASSERT(ret == 0, "KVM_SET_USER_MEMORY_REGION IOCTL failed,\n"
			" rc: %i errno: %i slot: %i\n",
			ret, errno, PRIV_MEM_SLOT);

	pr_info("Mapping guest private pages 0x%x page_size 0x%x\n",
					mem_size/vm_get_page_size(vm),
					vm_get_page_size(vm));
	virt_map(vm, PRIV_MEM_GPA, PRIV_MEM_GPA,
					(mem_size/vm_get_page_size(vm)));


	// run vm
	printf("running vm\n");
	struct kvm_run* run = vcpu_state(vm, VCPU_ID);
	vcpu_run(vm, VCPU_ID);

	// cleanup
	printf("cleaning up\n");
	munmap(shared_mem, mem_size);
	close(priv_memfd);
	kvm_vm_free(vm);

	return 0;
}
