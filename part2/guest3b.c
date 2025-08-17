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

    // Load the values from memory at address 0x400
    for (int i = 0; i < 5; i++)
    {
        values[i] = *(int *)(0x400 + i * sizeof(int));
    }

    // Pass the consumed values to the hypervisor
    for (int i = 0; i < 5; i++)
    {
        HC_print32bit(values[i]); // Pass each value to the hypervisor
    }

    // Trap to hypervisor to signal consumption
    HC_print32bit(0x400); // Use HC_print32bit to signal consumption

    for (;;)
        asm("hlt" : /* empty */ : "a"(42) : "memory");
}