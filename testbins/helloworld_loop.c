#include <stdio.h>

int main(int ac, char **av)
{
	int i;
	for(i=0; 1; i++) {
		printf("Hello, world! %d\n", i);
		int j;
		for(j=0; j<100000000; ++j)
			i = i*7;
	}
	return 0;
}
