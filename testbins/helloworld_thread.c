#include <stdio.h>

#if defined(_WIN32) || defined(_WIN64)
#define OS_IS_WINDOWS
#endif

#if defined(OS_IS_WINDOWS)
#include <windows.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#endif

#if defined(OS_IS_WINDOWS)
DWORD WINAPI ThreadFunc(void* vargp)
#else
void *thread_func(void *vargp)
#endif
{
	int i;
	int myid = *(int *)vargp;
	for(i=0; i<1000; ++i) {
		printf("I'm thread %d.\n", myid);
#if defined(OS_IS_WINDOWS)
		Sleep(1000);
#else
		sleep(1);
#endif
	}

#if defined(OS_IS_WINDOWS)
	return 0;
#else
	return NULL;
#endif
}

int main(int ac, char **av)
{
	printf("Before Thread\n");

	DWORD ids[4] = {0, 1, 2, 3};
#if defined(OS_IS_WINDOWS)
	HANDLE hThreadArray[4];
	hThreadArray[0] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+0), 0, NULL);
	hThreadArray[1] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+1), 0, NULL);
	hThreadArray[2] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+2), 0, NULL);
	hThreadArray[3] = CreateThread(NULL, 0, ThreadFunc, (void *)(ids+3), 0, NULL);
	WaitForMultipleObjects(4, hThreadArray, TRUE, INFINITE);
#else
	pthread_t thread_id;
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+0));
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+1));
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+2));
	pthread_create(&thread_id, NULL, thread_func, (void *)(ids+3));
	pthread_join(thread_id, NULL);
#endif

	return 0;
}
