#include <stddef.h>
#include <stdint.h>

// static void outb(uint16_t port, uint8_t value)
// {
//     asm("outb %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
// }

static inline void outb_32(uint16_t port, uint32_t value)
{
    asm("outl %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
}

void HC_print32bit(uint32_t val)
{
    outb_32(0xEA, val);
}

void
    __attribute__((noreturn))
    __attribute__((section(".start")))
    _start(void)
{
    int values[5];
    for (int i = 0; i < 5; i++)
    {
        values[i] = i; // Produce values 0, 1, 2, 3, 4
    }

    // Store the values in memory at address 0x400
    for (int i = 0; i < 5; i++)
    {
        *(int *)(0x400 + i * sizeof(int)) = values[i];
    }

    // Trap to hypervisor to pass the base address of the array
    HC_print32bit(0x400); // Use HC_print32bit to pass the base address

    for (;;)
        asm("hlt" : /* empty */ : "a"(42) : "memory");
}