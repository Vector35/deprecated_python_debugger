#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int ac, char **av)
{
	printf("start\n");

	if(ac>1 && !strcmp(av[1], "divzero")) {
		printf("dividing by zero\n");
		return ac/0;
	}

	printf("end\n");
	return 0;
}
