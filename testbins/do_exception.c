#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char **av)
{
	printf("start\n");

	if(!strcmp(av[1], "segfault")) {
		printf("accessing from 0xDEADBEEF\n");
		return *(int *)0xDEADBEEF;
	}

	if(!strcmp(av[1], "illegalinstr")) {
		unsigned char buf[] = {
			0x90,
			0x90,
			0x66, 0x06,	// push es on x86, invalid in x64
			0x0f, 0xb9,	// ud2b
			0x0f, 0x0b,	// ud2
			0xfe, 0xf0,
			0x90,
			0x90,
		};
		typedef int (*PFOO)(void);
		PFOO bar = (PFOO)buf;
		return bar();
	}

	if(!strcmp(av[1], "divzero")) {
		printf("dividing by zero\n");
		return ac/0;
	}

	printf("end\n");
	return 0;
}
