/*
	dbgeng is the "engine" behind WinDBG

	It's mainly a blocking call and callback model.

	You set things up, then call control->WaitForEvent() which blocks and while
	target is running, your event callbacks are called. While blocking, dbgeng calls your
	callbacks to notify you of events, and you return values that let dbgeng know how to
	proceed. For instance, after EventCallbacks::Breakpoint(), you can return DEBUG_STATUS_GO
	to say "carry on".

	If WaitForEvent() returns due to timeout, you're not forced to call it
	again. You can treat it like a separate entity and interact with it
	asynchronously. For example, breaking into the target with
	control->SetInterrupt() or quering its status with
	control->GetExecutionStatus().

	There are a few statuses:
	1) Session Status, reported from EventCallbacks::SessionStatus()
		DEBUG_SESSION_END, DEBUG_SESSION_ACTIVE, DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE,
		DEBUG_SESSION_END_SESSION_ACTIVE_DETACH, DEBUG_SESSION_END_SESSION_PASSIVE,
		DEBUG_SESSION_REBOOT, DEBUG_SESSION_HIBERNATE, DEBUG_SESSION_FAILURE
	2) Values returned from WaitForEvent()
		S_OK, S_FALSE, E_PENDING, E_UNEXPECTED, E_FAIL
	3) Execution status
		- returned by you from methods like EventCallbacks::BreakPoint()
		- reported to you after calling IDebugControl::GetExecutionStatus()
		- set by you when calling IDebugControl::SetExecutionStatus()
		- reported to you in event callback ChangeEngineState() with DEBUG_CES_EXECUTION_STATUS
		DEBUG_STATUS_GO, 					DEBUG_STATUS_GO_HANDLED, 	DEBUG_STATUS_GO_NOT_HANDLED,
		DEBUG_STATUS_STEP_OVER, 			DEBUG_STATUS_STEP_INTO, 	DEBUG_STATUS_BREAK,
		DEBUG_STATUS_NO_DEBUGGEE, 			DEBUG_STATUS_STEP_BRANCH, 	DEBUG_STATUS_IGNORE_EVENT,
		DEBUG_STATUS_RESTART_REQUESTED, 	DEBUG_STATUS_REVERSE_GO,
		DEBUG_STATUS_REVERSE_STEP_BRANCH, 	DEBUG_STATUS_REVERSE_STEP_OVER,
		DEBUG_STATUS_REVERSE_STEP_INTO, 	DEBUG_STATUS_OUT_OF_SYNC,
		DEBUG_STATUS_WAIT_INPUT, 			DEBUG_STATUS_TIMEOUT,

	debugging session model:
	https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-session-and-execution-model

*/

#include <stdio.h>
#include <stdint.h>

#include <windows.h>
#include <dbgeng.h>

#define EASY_CTYPES_SPEC extern "C" __declspec(dllexport)

#define ERROR_UNSPECIFIED -1
#define ERROR_NO_DBGENG_INTERFACES -2
#define ERROR_DBGENG_API -3

// dbgeng's interfaces
IDebugClient *g_Client = NULL;
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugcontrol
IDebugControl *g_Control = NULL;
IDebugDataSpaces *g_Data = NULL;
IDebugRegisters *g_Registers = NULL;
IDebugSymbols *g_Symbols = NULL;
IDebugSystemObjects *g_Objects = NULL;

ULONG g_ExitCode;

ULONG lastSessionStatus;
bool b_PROCESS_CREATED;
ULONG64 image_base;

/* forward declarations */
void status_to_str(ULONG status, char *str);

/*****************************************************************************/
/* EVENT CALLBACKS */
/*****************************************************************************/

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugeventcallbacks

class EventCallbacks : public DebugBaseEventCallbacks
{
	public:

STDMETHOD_(ULONG,AddRef)(THIS)
{
	printf("EventCallbacks::AddRef()\n");
	return 1;
}

STDMETHOD_(ULONG,Release)(THIS)
{
	printf("EventCallbacks::Release()\n");
	return 0;
}

STDMETHOD(GetInterestMask(THIS_ OUT PULONG Mask))
{
	printf("EventCallbacks::GetInterestMask()\n");

	/* we want it all! */
	*Mask = 0;
	*Mask |= DEBUG_EVENT_BREAKPOINT;
	*Mask |= DEBUG_EVENT_EXCEPTION;
	*Mask |= DEBUG_EVENT_CREATE_THREAD;
	*Mask |= DEBUG_EVENT_EXIT_THREAD;
	*Mask |= DEBUG_EVENT_CREATE_PROCESS;
	*Mask |= DEBUG_EVENT_EXIT_PROCESS;
	*Mask |= DEBUG_EVENT_LOAD_MODULE;
	*Mask |= DEBUG_EVENT_UNLOAD_MODULE;
	*Mask |= DEBUG_EVENT_SYSTEM_ERROR;
	*Mask |= DEBUG_EVENT_SESSION_STATUS;
	*Mask |= DEBUG_EVENT_CHANGE_DEBUGGEE_STATE;
	*Mask |= DEBUG_EVENT_CHANGE_ENGINE_STATE;
	*Mask |= DEBUG_EVENT_CHANGE_SYMBOL_STATE;

	return S_OK;
}

STDMETHOD(Breakpoint)(
	THIS_ IN PDEBUG_BREAKPOINT Bp
)
{
	printf("EventCallbacks::Breakpoint()\n");
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(Exception)(
	THIS_ IN PEXCEPTION_RECORD64 Exception,
	IN ULONG FirstChance
)
{
	// remember, at this point, the debugger status is at DEBUG_STATUS_BREAK
	printf("EventCallbacks::Exception()\n");

	if(FirstChance)
		printf("(first chance)\n");
	else
		printf("(second chance)\n");

	printf("\n");

	printf( "EXCEPTION_RECORD64:\n"
			"ExceptionCode: 0x%I32x (",
			Exception->ExceptionCode);

	switch(Exception->ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			printf("EXCEPTION_ACCESS_VIOLATION"); break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			printf("EXCEPTION_DATATYPE_MISALIGNMENT"); break;
		case EXCEPTION_BREAKPOINT:
			printf("EXCEPTION_BREAKPOINT"); break;
		case EXCEPTION_SINGLE_STEP:
			printf("EXCEPTION_SINGLE_STEP"); break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			printf("EXCEPTION_ARRAY_BOUNDS_EXCEEDED"); break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			printf("EXCEPTION_FLT_DENORMAL_OPERAND"); break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			printf("EXCEPTION_FLT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			printf("EXCEPTION_FLT_INEXACT_RESULT"); break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			printf("EXCEPTION_FLT_INVALID_OPERATION"); break;
		case EXCEPTION_FLT_OVERFLOW:
			printf("EXCEPTION_FLT_OVERFLOW"); break;
		case EXCEPTION_FLT_STACK_CHECK:
			printf("EXCEPTION_FLT_STACK_CHECK"); break;
		case EXCEPTION_FLT_UNDERFLOW:
			printf("EXCEPTION_FLT_UNDERFLOW"); break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			printf("EXCEPTION_INT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_INT_OVERFLOW:
			printf("EXCEPTION_INT_OVERFLOW"); break;
		case EXCEPTION_PRIV_INSTRUCTION:
			printf("EXCEPTION_PRIV_INSTRUCTION"); break;
		case EXCEPTION_IN_PAGE_ERROR:
			printf("EXCEPTION_IN_PAGE_ERROR"); break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			printf("EXCEPTION_ILLEGAL_INSTRUCTION"); break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			printf("EXCEPTION_NONCONTINUABLE_EXCEPTION"); break;
		case EXCEPTION_STACK_OVERFLOW:
			printf("EXCEPTION_STACK_OVERFLOW"); break;
		case EXCEPTION_INVALID_DISPOSITION:
			printf("EXCEPTION_INVALID_DISPOSITION"); break;
		case EXCEPTION_GUARD_PAGE:
			printf("EXCEPTION_GUARD_PAGE"); break;
		case EXCEPTION_INVALID_HANDLE:
			printf("EXCEPTION_INVALID_HANDLE"); break;
		case 0xe06d7363:
			printf("C++ Exception"); break;
		//case EXCEPTION_POSSIBLE_DEADLOCK:
		//	printf("EXCEPTION_POSSIBLE_DEADLOCK"); break;
		default:
			printf("EXCEPTION_WTF");
	}

	printf(")\n"
			"ExceptionFlags: 0x%08I32x\n"
			"ExceptionRecord: 0x%016I64x\n"
			"ExceptionAddress: 0x%016I64x\n"
			"NumberParameters: 0x%08I32x\n",
			Exception->ExceptionFlags,
			Exception->ExceptionRecord,
			Exception->ExceptionAddress,
			Exception->NumberParameters
		  );

	return DEBUG_STATUS_NO_CHANGE;

	if(FirstChance)
	{
		/* this will bring dbgeng out of "inside a wait" state, ie: WaitForEvent() will return */
		printf("returning DEBUG_STATUS_GO_NOT_HANDLED\n");
		return DEBUG_STATUS_GO_NOT_HANDLED;
	}
	else
	{
		printf("returning DEBUG_STATUS_BREAK\n");
		//g_EventCallbacksRequestsQuit = TRUE;
		return DEBUG_STATUS_BREAK;
	}
}

STDMETHOD(CreateThread)(
        THIS_
        _In_ ULONG64 Handle,
        _In_ ULONG64 DataOffset,
        _In_ ULONG64 StartOffset
        )
{
	printf("EventCallbacks::CreateThread(Handle=%016I64x DataOffset=%016I64X StartOffset=%016I64X)\n",
		Handle, DataOffset, StartOffset);
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(ExitThread)(
        THIS_
        _In_ ULONG ExitCode
        )
{
	printf("EventCallbacks::ExitThread(ExitCode:%d)\n", ExitCode);
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(CreateProcess)(
		THIS_
		IN ULONG64 ImageFileHandle,
		IN ULONG64 Handle,
		IN ULONG64 BaseOffset,
		IN ULONG ModuleSize,
		IN PCSTR ModuleName,
		IN PCSTR ImageName,
		IN ULONG CheckSum,
		IN ULONG TimeDateStamp,
		IN ULONG64 InitialThreadHandle,
		IN ULONG64 ThreadDataOffset,
		IN ULONG64 StartOffset
		)
{
	printf("EventCallbacks::CreateProcess(BaseOffset=0x%016I64X)\n", BaseOffset);

	image_base = BaseOffset;
	b_PROCESS_CREATED = true;

	UNREFERENCED_PARAMETER(ImageFileHandle);
	UNREFERENCED_PARAMETER(Handle);
	UNREFERENCED_PARAMETER(ModuleSize);
	UNREFERENCED_PARAMETER(ModuleName);
	UNREFERENCED_PARAMETER(CheckSum);
	UNREFERENCED_PARAMETER(TimeDateStamp);
	UNREFERENCED_PARAMETER(InitialThreadHandle);
	UNREFERENCED_PARAMETER(ThreadDataOffset);
	UNREFERENCED_PARAMETER(StartOffset);

	HRESULT hResult;

	return DEBUG_STATUS_BREAK;
	//return DEBUG_STATUS_GO;
}

STDMETHOD(LoadModule)(
		THIS_
		IN ULONG64 ImageFileHandle,
		IN ULONG64 BaseOffset,
		IN ULONG ModuleSize,
		IN PCSTR ModuleName,
		IN PCSTR ImageName,
		IN ULONG CheckSum,
		IN ULONG TimeDateStamp
		)
{
	UNREFERENCED_PARAMETER(ImageFileHandle);
	UNREFERENCED_PARAMETER(ModuleSize);
	UNREFERENCED_PARAMETER(ModuleName);
	UNREFERENCED_PARAMETER(CheckSum);
	UNREFERENCED_PARAMETER(TimeDateStamp);

	HRESULT hRes;

	//printf("EventCallbacks::LoadModule()\n");
	printf("loaded module %s to address %I64x\n", ModuleName, BaseOffset);

	return DEBUG_STATUS_GO;
}

STDMETHOD(UnloadModule)(
        THIS_
        _In_opt_ PCSTR ImageBaseName,
        _In_ ULONG64 BaseOffset
        )
{
	printf("EventCallbacks::UnloadModule()\n");
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SystemError)(
        THIS_
        _In_ ULONG Error,
        _In_ ULONG Level
        )
{
	printf("EventCallbacks::UnloadModule()\n");
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SessionStatus)(
		THIS_
		IN ULONG SessionStatus
		)
{
	printf("EventCallbacks::SessionStatus()\n");
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus

	lastSessionStatus = SessionStatus;

	switch(SessionStatus)
	{
		case DEBUG_SESSION_END:
			printf("\tDEBUG_SESSION_END\n");

			HRESULT hResult;

			ULONG exit_code;
			hResult = g_Client->GetExitCode(&exit_code);

			if(hResult == S_FALSE)
			{
				printf("error getting return code, dude still running!\n");
			}
			else if(hResult == S_OK)
			{
				if(exit_code == STILL_ACTIVE)
				{
					printf("STILL ACTIVE, WTF!\n");
				}

				printf("passing back exit code %08I32x\n", exit_code);
				return exit_code;
			}
			else
			{
				printf("wtf's up with GetExitCode() ?\n");
			}
			break;
		case DEBUG_SESSION_ACTIVE:
			printf("\tDEBUG_SESSION_ACTIVE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE:
			printf("\tDEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_DETACH:
			printf("\tDEBUG_SESSION_END_SESSION_ACTIVE_DETACH\n");
			break;
		case DEBUG_SESSION_END_SESSION_PASSIVE:
			printf("\tDEBUG_SESSION_END_SESSION_PASSIVE\n");
			break;
		case DEBUG_SESSION_REBOOT:
			printf("\tDEBUG_SESSION_REBOOT\n");
			break;
		case DEBUG_SESSION_HIBERNATE:
			printf("\tDEBUG_SESSION_HIBERNATE\n");
			break;
		case DEBUG_SESSION_FAILURE:
			printf("\tDEBUG_SESSION_FAILURE\n");
			break;
		default:
			printf("\tDEBUG_SESSION_WTF: %d\n", SessionStatus);
	}

	return S_OK;
}

STDMETHOD(ChangeDebuggeeState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
{
	printf("EventCallbacks::ChangeDebuggeeState()\n");
	if(Flags & DEBUG_CDS_REGISTERS)
		printf("\tDEBUG_CDS_REGISTERS\n");
	if(Flags & DEBUG_CDS_DATA)
		printf("\tDEBUG_CDS_DATA\n");
	if(Flags & DEBUG_CDS_REFRESH)
		printf("\tDEBUG_CDS_REFRESH\n");

	return DEBUG_STATUS_NO_CHANGE;
}

// Engine state has changed.
STDMETHOD(ChangeEngineState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
{
	char buf[64];
	printf("EventCallbacks::ChangeEngineState(0x%08X)\n", Flags);

	if(Flags & DEBUG_CES_CURRENT_THREAD) {
		if(Argument == DEBUG_ANY_ID)
			strcpy(buf, "TID:DEBUG_ANY_ID");
		else
			sprintf(buf, "TID:%lld", Argument);
		printf("\tDEBUG_CES_CURRENT_THREAD (%s)\n", buf);
	}
	if(Flags & DEBUG_CES_EFFECTIVE_PROCESSOR)
		printf("\tDEBUG_CES_EFFECTIVE_PROCESSOR\n");
	if(Flags & DEBUG_CES_BREAKPOINTS)
		printf("\tDEBUG_CES_BREAKPOINTS\n");
	if(Flags & DEBUG_CES_CODE_LEVEL)
		printf("\tDEBUG_CES_CODE_LEVEL\n");
	if(Flags & DEBUG_CES_EXECUTION_STATUS) {
		status_to_str(Argument, buf);
		printf("\tDEBUG_CES_EXECUTION_STATUS (%s)\n", buf);

		//if(Argument == DEBUG_STATUS_GO) {
		//	printf("\treinforcing the GO\n");
		//	return DEBUG_STATUS_GO;
		//}
	}
	if(Flags & DEBUG_CES_SYSTEMS)
		printf("\tDEBUG_CES_SYSTEMS\n");
	if(Flags & DEBUG_CES_ENGINE_OPTIONS)
		printf("\tDEBUG_CES_ENGINE_OPTIONS\n");
	if(Flags & DEBUG_CES_LOG_FILE)
		printf("\tDEBUG_CES_LOG_FILE\n");
	if(Flags & DEBUG_CES_RADIX)
		printf("\tDEBUG_CES_RADIX\n");
	if(Flags & DEBUG_CES_EVENT_FILTERS)
		printf("\tDEBUG_CES_EVENT_FILTERS\n");
	if(Flags & DEBUG_CES_PROCESS_OPTIONS)
		printf("\tDEBUG_CES_PROCESS_OPTIONS\n");
	if(Flags & DEBUG_CES_EXTENSIONS)
		printf("\tDEBUG_CES_EXTENSIONS\n");
	if(Flags & DEBUG_CES_ASSEMBLY_OPTIONS)
		printf("\tDEBUG_CES_ASSEMBLY_OPTIONS\n");
	if(Flags & DEBUG_CES_EXPRESSION_SYNTAX)
		printf("\tDEBUG_CES_EXPRESSION_SYNTAX\n");
	if(Flags & DEBUG_CES_TEXT_REPLACEMENTS)
		printf("\tDEBUG_CES_TEXT_REPLACEMENTS\n");

	return DEBUG_STATUS_NO_CHANGE;
}

// Symbol state has changed.
STDMETHOD(ChangeSymbolState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
		)
{
	printf("EventCallbacks::ChangeSymbolState()\n");

	if(Flags & DEBUG_CSS_LOADS)
		printf("DEBUG_CSS_LOADS");
	if(Flags & DEBUG_CSS_UNLOADS)
		printf("DEBUG_CSS_UNLOADS");
	if(Flags & DEBUG_CSS_SCOPE)
		printf("DEBUG_CSS_SCOPE");
	if(Flags & DEBUG_CSS_PATHS)
		printf("DEBUG_CSS_PATHS");
	if(Flags & DEBUG_CSS_SYMBOL_OPTIONS)
		printf("DEBUG_CSS_SYMBOL_OPTIONS");
	if(Flags & DEBUG_CSS_TYPE_OPTIONS)
		printf("DEBUG_CSS_TYPE_OPTIONS");
	if(Flags & DEBUG_CSS_COLLAPSE_CHILDREN)
		printf("DEBUG_CSS_COLLAPSE_CHILDREN");

	return DEBUG_STATUS_NO_CHANGE;
}

}; // class EventCallbacks

EventCallbacks g_EventCb;

/*****************************************************************************/
/* MISC UTILITIES */
/*****************************************************************************/

int wait(int timeout)
{
	HRESULT hResult;

	hResult = g_Control->WaitForEvent(
		0, /* flags */
		timeout /* timeout (ms) (INFINITE == eat events until "break" event); */
	);
	printf("WaitForEvent() returned %08I32x\n", hResult);

	switch(hResult) {
		case S_OK:
			//printf("S_OK (successful)\n");
			break;
		case S_FALSE: printf("S_FALSE (timeout expired)\n"); break;
		case E_PENDING: printf("E_PENDING (exit interrupt issued, target unavailable)\n"); break;
		case E_UNEXPECTED: printf("E_UNEXPECTED (outstanding input request, or no targets generate events)\n"); break;
		case E_FAIL: printf("E_FAIL (engine already waiting for event)\n"); break;
		default:
			printf("unknown reply from WaitForEvent(): %d\n", hResult);
	}

	if(hResult == S_OK)
		return 0;
	else
		return -1;
}

void status_to_str(ULONG status, char *str)
{
	*str = '\0';

	sprintf(str, "0x%08X ", status);

	if(status & DEBUG_STATUS_INSIDE_WAIT)
		strcat(str, "DEBUG_STATUS_INSIDE_WAIT|");
	if(status & DEBUG_STATUS_WAIT_TIMEOUT)
		strcat(str, "DEBUG_STATUS_WAIT_TIMEOUT|");

	status = status & 0x1f;
	if(status == DEBUG_STATUS_NO_CHANGE)
		strcat(str, "DEBUG_STATUS_NO_CHANGE");
	else if(status == DEBUG_STATUS_GO)
		strcat(str, "DEBUG_STATUS_GO");
	else if(status == DEBUG_STATUS_GO_HANDLED)
		strcat(str, "DEBUG_STATUS_GO_HANDLED");
	else if(status == DEBUG_STATUS_GO_NOT_HANDLED)
		strcat(str, "DEBUG_STATUS_GO_NOT_HANDLED");
	else if(status == DEBUG_STATUS_STEP_OVER)
		strcat(str, "DEBUG_STATUS_STEP_OVER");
	else if(status == DEBUG_STATUS_STEP_INTO)
		strcat(str, "DEBUG_STATUS_STEP_INTO");
	else if(status == DEBUG_STATUS_BREAK)
		strcat(str, "DEBUG_STATUS_BREAK");
	else if(status == DEBUG_STATUS_NO_DEBUGGEE)
		strcat(str, "DEBUG_STATUS_NO_DEBUGGEE");
	else if(status == DEBUG_STATUS_STEP_BRANCH)
		strcat(str, "DEBUG_STATUS_STEP_BRANCH");
	else if(status == DEBUG_STATUS_IGNORE_EVENT)
		strcat(str, "DEBUG_STATUS_IGNORE_EVENT");
	else if(status == DEBUG_STATUS_RESTART_REQUESTED)
		strcat(str, "DEBUG_STATUS_RESTART_REQUESTED");
	else if(status == DEBUG_STATUS_REVERSE_GO)
		strcat(str, "DEBUG_STATUS_REVERSE_GO");
	else if(status == DEBUG_STATUS_REVERSE_STEP_BRANCH)
		strcat(str, "DEBUG_STATUS_REVERSE_STEP_BRANCH");
	else if(status == DEBUG_STATUS_REVERSE_STEP_OVER)
		strcat(str, "DEBUG_STATUS_REVERSE_STEP_OVER");
	else if(status == DEBUG_STATUS_REVERSE_STEP_INTO)
		strcat(str, "DEBUG_STATUS_REVERSE_STEP_INTO");
	else if(status == DEBUG_STATUS_OUT_OF_SYNC)
		strcat(str, "DEBUG_STATUS_OUT_OF_SYNC");
	else if(status == DEBUG_STATUS_WAIT_INPUT)
		strcat(str, "DEBUG_STATUS_WAIT_INPUT");
	else if(status == DEBUG_STATUS_TIMEOUT)
		strcat(str, "DEBUG_STATUS_TIMEOUT");
	else
		strcat(str, "DEBUG_STATUS_LOOKUP_ERROR");
}

/*****************************************************************************/
/* ADAPTER API (binja/python calls this) */
/*****************************************************************************/

EASY_CTYPES_SPEC
int hello(void)
{
	int rc = -1;
	ULONG a, b;
	HRESULT hr;

	if(g_Objects->GetTotalNumberThreads(&a, &b) != S_OK) {
		printf("ERROR: GetTotalNumberThreads()\n");
		goto cleanup;
	}

	printf("number threads: %d\n", a);
	printf("total threads: %d\n", b);

	if(g_Objects->GetTotalNumberThreads(&a, &b) != S_OK) {
		printf("ERROR: GetTotalNumberThreads()\n");
		goto cleanup;
	}

	if(g_Objects->GetCurrentThreadId(&a) != S_OK) {
		printf("ERROR: GetCurrentThread()\n");
		goto cleanup;
	}

	printf("current thread: %d\n", a);

	printf("Hello, world!\n");
	printf("sizeof(ULONG)==%zd\n", sizeof(ULONG));
	printf("sizeof(S_OK)==%zd S_OK==%ld\n", sizeof(S_OK), S_OK);

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int echo(char *input)
{
	printf("you said: %s\n", input);
	return 0;
}

/* calls related to starting and stopping debug sessions */

EASY_CTYPES_SPEC
int process_start(char *path)
{
	int rc = -1;
	HRESULT hResult;

	b_PROCESS_CREATED = false;

	printf("starting process: %s\n", path);

	if(!g_Client) {
		printf("ERROR: interfaces not initialized\n");
		goto cleanup;
	}

	if(g_Client->CreateProcess(0, path, DEBUG_ONLY_THIS_PROCESS) != S_OK) {
		printf("ERROR: creating debug process\n");
		goto cleanup;
	}

	/* two requirements before target is considered successful started:
		1) EventCallbacks::SessionStatus() is given DEBUG_SESSION_ACTIVE
		2) EventCallbacks::CreateProcess() occurs
	*/

	/* wait for active session */
	for(int i=0; i<10; ++i) {
		if(lastSessionStatus == DEBUG_SESSION_ACTIVE && b_PROCESS_CREATED) {
			printf("process created!\n");
			rc = 0;
			goto cleanup;
		}

		wait(100);
	}

	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int process_attach(int pid)
{
	printf("attaching to process: %d\n", pid);

	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	if(g_Client->AttachProcess(0, pid, 0) != S_OK)
		return ERROR_DBGENG_API;

	/* wait for active session */
	for(int i=0; i<10; ++i) {
		if(lastSessionStatus == DEBUG_SESSION_ACTIVE && b_PROCESS_CREATED) {
			printf("process created!\n");
			return 0;
		}

		wait(INFINITE);
	}

	return ERROR_UNSPECIFIED;
}

EASY_CTYPES_SPEC
int process_detach(void)
{
	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	if(g_Client->DetachProcesses())
		return ERROR_DBGENG_API;

	return 0;
}

EASY_CTYPES_SPEC
int quit(void)
{
	int rc = -1;
	if(g_Client->EndSession(DEBUG_END_ACTIVE_TERMINATE) != S_OK)
		goto cleanup;
	rc = 0;
	cleanup:
	return rc;
}

/* calls related to execution control */

EASY_CTYPES_SPEC
int break_into(void)
{
	int rc = -1;
	if(g_Control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK) {
		printf("ERROR: SetInterrupt() failed\n");
		goto cleanup;
	}
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int go(void)
{
	int rc = -1;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK) {
		printf("ERROR: SetExecutionStatus(GO) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int step_into(void)
{
	int rc = -1;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK) {
		printf("ERROR: SetExecutionStatus(STEP_INTO) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int step_over(void)
{
	int rc = -1;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK) {
		printf("ERROR: SetExecutionStatus(STEP_OVER) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

/* calls related to breakpoints */

EASY_CTYPES_SPEC
int breakpoint_set(uint64_t addr, ULONG *id)
{
	IDebugBreakpoint *pidb = NULL;

	if(g_Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &pidb) != S_OK)
		return ERROR_DBGENG_API;

	pidb->GetId(id);
	pidb->SetOffset(addr);
	pidb->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	return 0;
}

EASY_CTYPES_SPEC
int breakpoint_clear(ULONG id)
{
	IDebugBreakpoint *pidb = NULL;

	if(g_Control->GetBreakpointById(id, &pidb) != S_OK)
		return ERROR_DBGENG_API;

	if(g_Control->RemoveBreakpoint(pidb) != S_OK)
		return ERROR_DBGENG_API;

	return 0;
}

/* calls related to state */
EASY_CTYPES_SPEC
int mem_read(uint64_t addr, uint32_t length, uint8_t *result)
{
	int rc = -1;
	ULONG bytes_read;

	if(g_Data->ReadVirtual(addr, result, length, &bytes_read) != S_OK) {
		printf("ERROR: ReadVirtual()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int mem_write(uint64_t addr, uint8_t *data, uint32_t len)
{
	int rc = -1;

	if(g_Data->WriteVirtual(addr, data, len, NULL) != S_OK) {
		printf("ERROR: WriteVirtual()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int reg_read(char *name, uint64_t *result)
{
	int rc = -1;

	ULONG reg_index;
	DEBUG_VALUE dv;

	if(g_Registers->GetIndexByName(name, &reg_index) != S_OK) {
		printf("ERROR: GetIndexByName()\n");
		goto cleanup;
	}

	if(g_Registers->GetValue(reg_index, &dv) != S_OK) {
		printf("ERROR: GetValue()\n");
		goto cleanup;
	}

	*result = dv.I64;

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int reg_write(char *name, uint64_t value)
{
	int rc = ERROR_UNSPECIFIED;

	ULONG reg_index;
	DEBUG_VALUE dv;

	if(g_Registers->GetIndexByName(name, &reg_index) != S_OK) {
		printf("ERROR: GetIndexByName()\n");
		goto cleanup;
	}
	printf("The value of register %s is %d\n", name, reg_index);

	dv.I64 = value;
	dv.Type = DEBUG_VALUE_INT64;
	HRESULT hr = g_Registers->SetValue(reg_index, &dv);
	if(hr != S_OK) {
		printf("ERROR: SetValue() returned %08X\n", hr);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int get_exec_status(ULONG *result)
{
	int rc = -1;
	ULONG status = -1;
	if(g_Control->GetExecutionStatus(&status) != S_OK) {
		printf("ERROR: GetExecutionStatus() failed\n");
		goto cleanup;
	}

	char buf[64];
	*result = status;
	status_to_str(status, buf);
	printf("get_exec_status() returning %s\n", buf);

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
uint64_t get_image_base(void)
{
	return image_base;
}

EASY_CTYPES_SPEC
int set_current_thread(ULONG id)
{
	int rc = -1;

	if(g_Objects->SetCurrentThreadId(id) != S_OK) {
		printf("ERROR: SetCurrentThreadId()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int get_current_thread(void)
{
	ULONG tid;
	if(g_Objects->GetCurrentThreadId(&tid) != S_OK) {
		printf("ERROR: GetCurrentThread()\n");
		return -1;
	}
	return tid;
}

EASY_CTYPES_SPEC
int get_number_threads(void)
{
	ULONG Total, LargestProcess;
	if(g_Objects->GetTotalNumberThreads(&Total, &LargestProcess) != S_OK) {
		printf("ERROR: GetTotalNumberThreads()\n");
		return -1;
	}
	return Total;
}

/*****************************************************************************/
/* ENTRYPOINT */
/*****************************************************************************/

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	// see https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain

	int rc = false;
	HRESULT hResult;

	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
			printf("DLL_PROCESS_ATTACH: creating debug interfaces\n");

			hResult = DebugCreate(__uuidof(IDebugClient), (void **)&g_Client);

			if(hResult != S_OK)
			{
				printf("ERROR: getting IDebugClient\n");
				goto cleanup;
			}

			if ((hResult = g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control)) != S_OK ||
				(hResult = g_Client->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&g_Data)) != S_OK ||
				(hResult = g_Client->QueryInterface(__uuidof(IDebugRegisters), (void**)&g_Registers)) != S_OK ||
				(hResult = g_Client->QueryInterface(__uuidof(IDebugSymbols), (void**)&g_Symbols)) != S_OK ||
				(hResult = g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&g_Objects)) != S_OK)
			{
				printf("ERROR: getting client debugging interface\n");
				goto cleanup;
			}

			if ((hResult = g_Client->SetEventCallbacks(&g_EventCb)) != S_OK)
			{
				printf("ERROR: registering event callbacks\n");
				goto cleanup;
			}

			printf("debug interfaces created\n");
			break;

		case DLL_PROCESS_DETACH:
			printf("DLL_PROCESS_DETACH: freeing debug interfaces\n");

			if (g_Control != NULL)
				g_Control->Release();

			if (g_Data != NULL)
				g_Data->Release();

			if (g_Registers != NULL)
				g_Registers->Release();

			if (g_Symbols != NULL)
				g_Symbols->Release();

			if (g_Objects != NULL)
				g_Objects->Release();

			if (g_Client != NULL)
			{
				g_Client->EndSession(DEBUG_END_PASSIVE);
				g_Client->Release();
			}

			printf("debug interfaces freed\n");

			break;

		case DLL_THREAD_ATTACH:
			printf("DLL_THREAD_ATTACH\n");
			break;

		case DLL_THREAD_DETACH:
			printf("DLL_THREAD_DETACH\n");
			break;

		default:
			printf("unknown fdwReason: %d\n", fdwReason);
			break;
	}

	rc = true;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int teardown(void)
{
	int rc = -1;

	rc = 0;
	cleanup:
	return rc;
}
