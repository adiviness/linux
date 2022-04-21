
// basic selftest allocating huge pages backed by shmem

#define _GNU_SOURCE /* for program_invocation_short_name */
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/kvm_para.h>
#include <linux/memfd.h>

#include <test_util.h>
#include <kvm_util.h>
#include <processor.h>


#define PRIV_MEM_SIZE 0x2000
#define VCPU_ID			0
#define MEM_SLOT 10
#define GUEST_ADDR 0x2000000

// taken from mmap man page
#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)

// page sizes
#define PAGE_SIZE 0x1000
#define _2MB_PAGE_SIZE ((PAGE_SIZE * 1024 / 2))
#define _1GB_PAGE_SIZE 0x40000000


static void guest_func(void) {
	uint8_t* pByte = GUEST_ADDR;
	for (size_t i = 0; i < _2MB_PAGE_SIZE; ++i) {
		*(pByte + i) = 0xFF;
	}
	GUEST_DONE();
}

void mmap_vm() {
	// setup vm
	struct kvm_vm* vm = vm_create_default(VCPU_ID, 0, &guest_func);

	int mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE
		| MAP_HUGETLB | MAP_HUGE_2MB;
	size_t mem_size = _2MB_PAGE_SIZE;

	void* shared_mem = mmap(NULL,
							mem_size,
							PROT_READ | PROT_WRITE,
							mmap_flags, -1, 0);
	TEST_ASSERT(shared_mem != MAP_FAILED, "Failed to mmap() host");

	struct kvm_userspace_memory_region region;
	region.slot = MEM_SLOT;
	region.flags = 0;
	region.guest_phys_addr = GUEST_ADDR;
	region.memory_size = _2MB_PAGE_SIZE;
	region.userspace_addr = shared_mem;
	int ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION, &region);
	TEST_ASSERT(ret == 0, "failed to allocate memory");

	printf("running vm\n");
	struct kvm_run* run = vcpu_state(vm, VCPU_ID);
	vcpu_run(vm, VCPU_ID);

	// cleanup
	printf("cleaning up\n");
	munmap(shared_mem, mem_size);
	kvm_vm_free(vm);
}

void memfd_create_vm() {
	// setup vm
	struct kvm_vm* vm = vm_create_default(VCPU_ID, 0, &guest_func);

	unsigned int memfd_flags = (MFD_HUGETLB | MFD_HUGE_2MB);
	size_t mem_size = _2MB_PAGE_SIZE;

	int memfd = memfd_create("blah_vm_private_mem", memfd_flags);
	TEST_ASSERT(memfd != -1, "Failed to create memfd");
	int ret = fallocate(memfd, 0, 0, mem_size);
	TEST_ASSERT(ret != -1, "fallocate failed");

	struct kvm_userspace_memory_region region;
	region.slot = MEM_SLOT;
	region.flags = 0;
	region.guest_phys_addr = GUEST_ADDR;
	region.memory_size = _2MB_PAGE_SIZE;
	// TODO how to get address from memfd file descriptor?
	//region.userspace_addr = shared_mem;
	ret = ioctl(vm_get_fd(vm), KVM_SET_USER_MEMORY_REGION, &region);
	TEST_ASSERT(ret == 0, "failed to allocate memory");
	printf("running vm\n");

	struct kvm_run* run = vcpu_state(vm, VCPU_ID);
	vcpu_run(vm, VCPU_ID);

	// cleanup
	printf("cleaning up\n");
	close(memfd);
	kvm_vm_free(vm);
}

int main(int argc, char** argv) {

	int ret;
	/* Tell stdout not to buffer its content */
	setbuf(stdout, NULL);

	printf("mmap version\n");
	mmap_vm();
	//printf("memfd_create version\n");
	//memfd_create_vm();

	return 0;
}
