#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)

struct vm
{
	int dev_fd;
	int vm_fd;
	char *mem;
};

struct vcpu
{
	int vcpu_fd;
	struct kvm_run *kvm_run;
};


void vm_init(struct vm *vm, size_t mem_size)
{
	int kvm_version;
	struct kvm_userspace_memory_region memreg;

	vm->dev_fd = open("/dev/kvm", O_RDWR);
	if (vm->dev_fd < 0)
	{
		perror("open /dev/kvm");
		exit(1);
	}

	kvm_version = ioctl(vm->dev_fd, KVM_GET_API_VERSION, 0);
	if (kvm_version < 0)
	{
		perror("KVM_GET_API_VERSION");
		exit(1);
	}

	if (kvm_version != KVM_API_VERSION)
	{
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
				kvm_version, KVM_API_VERSION);
		exit(1);
	}

	vm->vm_fd = ioctl(vm->dev_fd, KVM_CREATE_VM, 0);
	if (vm->vm_fd < 0)
	{
		perror("KVM_CREATE_VM");
		exit(1);
	}

	if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0)
	{
		perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (vm->mem == MAP_FAILED)
	{
		perror("mmap mem");
		exit(1);
	}

	madvise(vm->mem, mem_size, MADV_MERGEABLE);

	memreg.slot = 0;
	memreg.flags = 0;
	memreg.guest_phys_addr = 0;
	memreg.memory_size = mem_size;
	memreg.userspace_addr = (unsigned long)vm->mem;
	if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)
	{
		perror("KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
}

void vcpu_init(struct vm *vm, struct vcpu *vcpu)
{
	int vcpu_mmap_size;

	vcpu->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
	if (vcpu->vcpu_fd < 0)
	{
		perror("KVM_CREATE_VCPU");
		exit(1);
	}

	vcpu_mmap_size = ioctl(vm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0)
	{
		perror("KVM_GET_VCPU_MMAP_SIZE");
		exit(1);
	}

	vcpu->kvm_run = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE,
						 MAP_SHARED, vcpu->vcpu_fd, 0);
	if (vcpu->kvm_run == MAP_FAILED)
	{
		perror("mmap kvm_run");
		exit(1);
	}
}
int run_vm(struct vm *virtualMachinePointer, struct vcpu *virtualCpuPointer, size_t memoryCheckSizeValue) {
    // Structure for storing the current state of the CPU registers
    struct kvm_regs currentCpuRegisterStates;

    // Counters for tracking different exit reasons
    uint32_t totalExitCounterForVm = 0;    // Total number of exits from the VM
    uint32_t ioOutputExitCounterForVm = 0; // Count of IO output operations
    uint32_t ioInputExitCounterForVm = 0;  // Count of IO input operations

    // Variables for storing IO and memory values
    uint64_t currentMemoryValueForVm = 0;       // 64-bit variable to hold memory value
    uintptr_t current64BitAddressValue = 0;       // Pointer type variable for 64-bit addresses
    uint32_t current32BitValueForIoOperations = 0; // 32-bit variable for IO operations

    // Variable to hold the host virtual address after translation
    uintptr_t hostVirtualAddressAfterTranslation = 0;

    // Main execution loop for the virtual machine
    for (;;) {
        // Reset values for the new iteration
        currentMemoryValueForVm = current32BitValueForIoOperations = current64BitAddressValue = 0;

        // Execute the virtual CPU
        if (ioctl(virtualCpuPointer->vcpu_fd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN"); // Print error if KVM_RUN fails
            exit(1);           // Exit if an error occurs
        }

        // Increment the total exit count for tracking
        totalExitCounterForVm++;

        // Switch to handle different exit reasons from the VM
        switch (virtualCpuPointer->kvm_run->exit_reason) {
            // Handle case when the VM is requested to halt
            case KVM_EXIT_HLT:
                goto vmExitCheck; // Jump to exit check logic

            // Handle IO operations
            case KVM_EXIT_IO: {
                // Increment the appropriate exit counter based on direction
                if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                    ioOutputExitCounterForVm++; // Increment output counter
                } else if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_IN) {
                    ioInputExitCounterForVm++; // Increment input counter
                }

		// Get a pointer to the KVM run data area based on the offset
		char* kvmDataAreaPointer = (char*)virtualCpuPointer->kvm_run + virtualCpuPointer->kvm_run->io.data_offset;

		// Handle different IO ports
		switch (virtualCpuPointer->kvm_run->io.port) {
			// Print an 8-bit character for port 0xE9
			case 0xE9: {
				if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
					fwrite(kvmDataAreaPointer, virtualCpuPointer->kvm_run->io.size, 1, stdout); // Output to stdout
					fflush(stdout); // Flush the output buffer
				}
				break;
			}

                    // Print a 32-bit number for port 0xEA
                    case 0xEA: {
                        if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                            uint32_t outputValue32BitForIo = 0;
                            memcpy(&outputValue32BitForIo, kvmDataAreaPointer, sizeof(uint32_t)); // Copy data to outputValue
                            printf("%u\n", outputValue32BitForIo); // Print the value
                            fflush(stdout); // Flush the output buffer
                        }
                        break;
                    }

			// Get total exit count for port 0xEB
			case 0xEB: {
				if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_IN) {
					memcpy(kvmDataAreaPointer, &totalExitCounterForVm, sizeof(uint32_t)); // Send total exit count
				}
				break;
			}

                    // Print a string from guest memory for port 0xEC
                    case 0xEC: {
                        if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
                            uintptr_t guestStringAddressValue = 0;
                            memcpy(&guestStringAddressValue, kvmDataAreaPointer, sizeof(uintptr_t)); // Get guest string address
                            char* guestStringPointer = &(virtualMachinePointer->mem[guestStringAddressValue]); // Access the guest memory
                            printf("%s", guestStringPointer); // Print the string
                        }
                        break;
                    }

			// Get exit counts by type for port 0xED
			case 0xED: {
				if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_IN) {
					const int exitCountBufferSizeForVm = 100; // Size for exit count buffer
					char* exitCountBufferPointer = (char*)malloc(exitCountBufferSizeForVm); // Allocate memory for exit count buffer
					
					// Calculate buffer offset relative to VM memory
					uintptr_t bufferOffsetValueForVm = (uintptr_t)exitCountBufferPointer - (uintptr_t)virtualMachinePointer->mem;

					// Format exit count string
					snprintf(exitCountBufferPointer, exitCountBufferSizeForVm, 
								"IO in: %u\nIO out: %u\n", 
								ioInputExitCounterForVm, ioOutputExitCounterForVm);

					// Copy the buffer offset to KVM data area
					memcpy(kvmDataAreaPointer, &bufferOffsetValueForVm, sizeof(uintptr_t));
				}
				break;
			}

				// Translate Guest Virtual Address to Host Virtual Address for port 0xEE
				case 0xEE: {
					if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_OUT) {
						uint32_t guestVirtualAddressValueForVm = 0;
						memcpy(&guestVirtualAddressValueForVm, kvmDataAreaPointer, sizeof(uint32_t)); // Get guest virtual address

						struct kvm_translation addressTranslationForVm = {
							.linear_address = guestVirtualAddressValueForVm // Set linear address for translation
						};

						// Translate guest virtual to physical address
						if ((ioctl(virtualCpuPointer->vcpu_fd, KVM_TRANSLATE, &addressTranslationForVm) == -1) || 
							(addressTranslationForVm.valid == 0)) {
							printf("Invalid GVA\n"); // Print error for invalid GVA
							hostVirtualAddressAfterTranslation = 0; // Reset host virtual address
						} else {
							hostVirtualAddressAfterTranslation = (uintptr_t)virtualMachinePointer->mem + addressTranslationForVm.physical_address; // Calculate host address
						}
					}
					break;
				}

		// Return Host Virtual Address for port 0xEF
		case 0xEF: {
			if (virtualCpuPointer->kvm_run->io.direction == KVM_EXIT_IO_IN) {
				memcpy(kvmDataAreaPointer, &hostVirtualAddressAfterTranslation, sizeof(uintptr_t)); // Send host virtual address
			}
			break;
		}
                }

                continue; // Continue the loop for the next iteration
            }

            // Handle unexpected exit reasons
            default:
                fprintf(stderr, "Got exit_reason %d, expected KVM_EXIT_HLT (%d)\n",
                        virtualCpuPointer->kvm_run->exit_reason, KVM_EXIT_HLT);
                exit(1); // Exit on unexpected reason
        }
    }

vmExitCheck:
    // Get the final CPU register state
    if (ioctl(virtualCpuPointer->vcpu_fd, KVM_GET_REGS, &currentCpuRegisterStates) < 0) {
        perror("KVM_GET_REGS"); // Print error if getting registers fails
        exit(1); // Exit on error
    }

    // Verify expected result in the RAX register
    if (currentCpuRegisterStates.rax != 42) {
        printf("Wrong result: {E,R,}AX is %lld\n", currentCpuRegisterStates.rax); // Print error message
        return 0; // Return failure
    }

    // Verify expected result in memory
    memcpy(&currentMemoryValueForVm, &virtualMachinePointer->mem[0x400], memoryCheckSizeValue); // Copy memory value to check
    if (currentMemoryValueForVm != 42) {
        printf("Wrong result: memory at 0x400 is %lld\n",
               (unsigned long long)currentMemoryValueForVm); // Print error for unexpected memory value
        return 0; // Return failure
    }

    return 1; // Return success if all checks pass
}



extern const unsigned char guest16[], guest16_end[];

int run_real_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing real mode\n");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		exit(1);
	}

	sregs.cs.selector = 0;
	sregs.cs.base = 0;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest16, guest16_end - guest16);
	return run_vm(vm, vcpu, 2);
}

static void setup_protected_mode(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};

	sregs->cr0 |= CR0_PE; /* enter protected mode */

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

extern const unsigned char guest32[], guest32_end[];

int run_protected_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing protected mode\n");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end - guest32);
	return run_vm(vm, vcpu, 4);
}

static void setup_paged_32bit_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint32_t pd_addr = 0x2000;
	uint32_t *pd = (void *)(vm->mem + pd_addr);

	/* A single 4MB page to cover the memory region */
	pd[0] = PDE32_PRESENT | PDE32_RW | PDE32_USER | PDE32_PS;
	/* Other PDEs are left zeroed, meaning not present. */

	sregs->cr3 = pd_addr;
	sregs->cr4 = CR4_PSE;
	sregs->cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = 0;
}

int run_paged_32bit_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 32-bit paging\n");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_protected_mode(&sregs);
	setup_paged_32bit_mode(vm, &sregs);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest32, guest32_end - guest32);
	return run_vm(vm, vcpu, 4);
}

extern const unsigned char guest64[], guest64_end[];

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.present = 1,
		.type = 11, /* Code: execute, read, accessed */
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};

	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
{
	uint64_t pml4_addr = 0x2000;
	uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

	uint64_t pdpt_addr = 0x3000;
	uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

	uint64_t pd_addr = 0x4000;
	uint64_t *pd = (void *)(vm->mem + pd_addr);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}

int run_long_mode(struct vm *vm, struct vcpu *vcpu)
{
	struct kvm_sregs sregs;
	struct kvm_regs regs;

	printf("Testing 64-bit mode\n");

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		exit(1);
	}

	setup_long_mode(vm, &sregs);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		exit(1);
	}

	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = 0;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		exit(1);
	}

	memcpy(vm->mem, guest64, guest64_end - guest64);
	return run_vm(vm, vcpu, 8);
}

int main(int argc, char **argv)
{
	struct vm vm;
	struct vcpu vcpu;
	enum
	{
		REAL_MODE,
		PROTECTED_MODE,
		PAGED_32BIT_MODE,
		LONG_MODE,
	} mode = REAL_MODE;
	int opt;

	while ((opt = getopt(argc, argv, "rspl")) != -1)
	{
		switch (opt)
		{
		case 'r':
			mode = REAL_MODE;
			break;

		case 's':
			mode = PROTECTED_MODE;
			break;

		case 'p':
			mode = PAGED_32BIT_MODE;
			break;

		case 'l':
			mode = LONG_MODE;
			break;

		default:
			fprintf(stderr, "Usage: %s [ -r | -s | -p | -l ]\n",
					argv[0]);
			return 1;
		}
	}

	vm_init(&vm, 0x200000);
	vcpu_init(&vm, &vcpu);

	switch (mode)
	{
	case REAL_MODE:
		return !run_real_mode(&vm, &vcpu);

	case PROTECTED_MODE:
		return !run_protected_mode(&vm, &vcpu);

	case PAGED_32BIT_MODE:
		return !run_paged_32bit_mode(&vm, &vcpu);

	case LONG_MODE:
		return !run_long_mode(&vm, &vcpu);
	}

	return 1;
}
