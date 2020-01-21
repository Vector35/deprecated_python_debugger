#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

void *thread_func(void *vargp) 
{
	int i;
	int myid = *(int *)vargp;
	for(i=0; i<1000; ++i) {
		printf("I'm thread %d.\n", myid);
		sleep(1); 
	}

	return NULL;
} 

int main(int ac, char **av)
{
	pthread_t thread_id; 
	printf("Before Thread\n");

	int ids[4] = {0, 1, 2, 3};
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+0)); 
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+1)); 
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+2)); 
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+3)); 
	pthread_join(thread_id, NULL); 

	return 0;
}
