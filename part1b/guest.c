#include <stddef.h>
#include <stdint.h>

static void outb(uint16_t port, uint8_t value)
{
	asm("outb %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
}

//this function will write 32 bit value to the specified I/O port, and it will be used to write 32 bit value to the I/O port 0xEA
static inline void outb_32(uint16_t port, uint32_t value)
{	
	//assenbly instruction like the above function but with 32 bit value
	asm("outl %0,%1" : /* empty */ : "a"(value), "Nd"(port) : "memory");
}

// this function will help us in reading the 8 bit value from the specified I/O port
static inline uint32_t input_value_from_port_function(uint16_t port)
{
	uint32_t input_value_from_port;
   // Assembly will take input from the specified port and store it in the ret variable
	asm("in %1, %0" : "=a"(input_value_from_port) : "Nd"(port) : "memory");
	return input_value_from_port;
}

void HC_print8bit(uint8_t val)
{
	outb(0xE9, val);
}

void HC_print32bit(uint32_t val)
{
	// val++;
	/* Write code here */
	outb_32(0xEA, val);
}

uint32_t HC_numExits()
{
	// uint32_t val = 0;
	/* Write code here */
	return input_value_from_port_function(0xEB);
	// return val;
}

void HC_printStr(char *str)
{
	// str++;
	/* Write code here */
	uintptr_t str_addr = (uintptr_t)str;	// Cast the string to a uintptr_t
	outb_32(0xEC,str_addr);

}

char *HC_numExitsByType()
{
	uint32_t input_value_from_port;	
	asm("in %1, %0" : "=a"(input_value_from_port) : "Nd"(0xED) : "memory");	
	char *ptr = (char *)(uintptr_t)input_value_from_port;	

	return ptr;
}

uint32_t HC_gvaToHva(uint32_t gva)
{
	// gva++;
	// uint32_t hva = 0;
	/* Write code here */
	outb_32(0xEE, (uint32_t)gva);

	uint32_t hva = input_value_from_port_function(0xEF); // Read the HVA from the I/O port 0xEF

	return hva;
}

void
	__attribute__((noreturn))
	__attribute__((section(".start")))
	_start(void)
{
	const char *p;

	for (p = "Hello 695!\n"; *p; ++p)
		HC_print8bit(*p);

	/*----------Don't modify this section. We will use grading script---------*/
	/*---Your submission will fail the testcases if you modify this section---*/
	HC_print32bit(2048);
	HC_print32bit(4294967295);

	uint32_t num_exits_a, num_exits_b;
	num_exits_a = HC_numExits();

	char *str = "CS695 Assignment 2\n";
	HC_printStr(str);

	num_exits_b = HC_numExits();

	HC_print32bit(num_exits_a);
	HC_print32bit(num_exits_b);

	char *firststr = HC_numExitsByType();
	uint32_t hva;
	hva = HC_gvaToHva(1024);
	HC_print32bit(hva);
	hva = HC_gvaToHva(4294967295);
	HC_print32bit(hva);
	char *secondstr = HC_numExitsByType();

	HC_printStr(firststr);
	HC_printStr(secondstr);
	/*------------------------------------------------------------------------*/

	*(long *)0x400 = 42;

	for (;;)
		asm("hlt" : /* empty */ : "a"(42) : "memory");
}
