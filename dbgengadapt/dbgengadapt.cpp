/*
	dbgeng is the "engine" behind WinDBG

	It's mainly a blocking call and callback model.

	You set things up, then call control->WaitForEvent() which blocks and while
	target is running, your event callbacks are called. While blocking, dbgeng calls your
	callbacks to notify you of events, and you return values that let dbgeng know how to
	proceed. For instance, after EventCallbacks::Breakpoint(), you can return DEBUG_STATUS_GO
	to say "carry on".

	If WaitForEvent() returns due to timeout and the target is still running, you can
	interact with the engine with queries like control->GetExecutionStatus() and interrupt
	the target with control->SetInterrupt().

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

#include <map>
#include <vector>
#include <string>
using namespace std;

#define EASY_CTYPES_SPEC extern "C" __declspec(dllexport)

#define ERROR_UNSPECIFIED -1
#define ERROR_NO_DBGENG_INTERFACES -2
#define ERROR_DBGENG_API -3

// dbgeng's interfaces
IDebugClient5 *g_Client = NULL;
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugcontrol
IDebugControl *g_Control = NULL;
IDebugDataSpaces *g_Data = NULL;
IDebugRegisters *g_Registers = NULL;
IDebugSymbols *g_Symbols = NULL;
IDebugSystemObjects *g_Objects = NULL;

EXCEPTION_RECORD64 g_last_exception64 = {0};
uint64_t g_last_breakpoint = 0;
ULONG64 g_image_base;

ULONG lastSessionStatus = DEBUG_SESSION_FAILURE;
bool b_PROCESS_CREATED = false;
bool b_PROCESS_EXITED = false;
bool b_AT_LEAST_ONE_BREAKPOINT = false;
ULONG g_process_exit_code;

/* forward declarations */
void status_to_str(ULONG status, char *str);

#define printf_debug(fmt, ...) { \
	char asd123[1024]; \
	sprintf(asd123, fmt, __VA_ARGS__); \
	OutputDebugString(asd123); \
	printf(asd123); \
}

#define printf_debug(x, ...) while(0);

/*****************************************************************************/
/* EVENT CALLBACKS */
/*****************************************************************************/

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugeventcallbacks

class EventCallbacks : public DebugBaseEventCallbacks
{
	public:

STDMETHOD_(ULONG,AddRef)(THIS)
{
	printf_debug("EventCallbacks::AddRef()\n");
	return 1;
}

STDMETHOD_(ULONG,Release)(THIS)
{
	printf_debug("EventCallbacks::Release()\n");
	return 0;
}

STDMETHOD(GetInterestMask(THIS_ OUT PULONG Mask))
{
	printf_debug("EventCallbacks::GetInterestMask()\n");

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
	printf_debug("EventCallbacks::Breakpoint()\n");

	ULONG64 addr;
	if(Bp->GetOffset(&addr) == S_OK) {
		printf_debug("\taddress: 0x%016I64x\n", addr);
		g_last_breakpoint = addr;
	}
	else
		printf_debug("\t(failed to get address)\n");

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(Exception)(
	THIS_ IN PEXCEPTION_RECORD64 Exception,
	IN ULONG FirstChance
)
{
	// remember, at this point, the debugger status is at DEBUG_STATUS_BREAK
	printf_debug("EventCallbacks::Exception()\n");
	g_last_exception64 = *Exception;

	printf_debug("\tFirstChance: 0x%08I32x\n", Exception->NumberParameters);
	printf_debug("\tEXCEPTION_RECORD64:\n"
			"\tExceptionCode: 0x%I32x (",
			Exception->ExceptionCode);

	switch(Exception->ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			printf_debug("EXCEPTION_ACCESS_VIOLATION"); break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			printf_debug("EXCEPTION_DATATYPE_MISALIGNMENT"); break;
		case EXCEPTION_BREAKPOINT:
			printf_debug("EXCEPTION_BREAKPOINT");
			b_AT_LEAST_ONE_BREAKPOINT = true;
			break;
		case EXCEPTION_SINGLE_STEP:
			printf_debug("EXCEPTION_SINGLE_STEP"); break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			printf_debug("EXCEPTION_ARRAY_BOUNDS_EXCEEDED"); break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			printf_debug("EXCEPTION_FLT_DENORMAL_OPERAND"); break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			printf_debug("EXCEPTION_FLT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			printf_debug("EXCEPTION_FLT_INEXACT_RESULT"); break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			printf_debug("EXCEPTION_FLT_INVALID_OPERATION"); break;
		case EXCEPTION_FLT_OVERFLOW:
			printf_debug("EXCEPTION_FLT_OVERFLOW"); break;
		case EXCEPTION_FLT_STACK_CHECK:
			printf_debug("EXCEPTION_FLT_STACK_CHECK"); break;
		case EXCEPTION_FLT_UNDERFLOW:
			printf_debug("EXCEPTION_FLT_UNDERFLOW"); break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			printf_debug("EXCEPTION_INT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_INT_OVERFLOW:
			printf_debug("EXCEPTION_INT_OVERFLOW"); break;
		case EXCEPTION_PRIV_INSTRUCTION:
			printf_debug("EXCEPTION_PRIV_INSTRUCTION"); break;
		case EXCEPTION_IN_PAGE_ERROR:
			printf_debug("EXCEPTION_IN_PAGE_ERROR"); break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			printf_debug("EXCEPTION_ILLEGAL_INSTRUCTION"); break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			printf_debug("EXCEPTION_NONCONTINUABLE_EXCEPTION"); break;
		case EXCEPTION_STACK_OVERFLOW:
			printf_debug("EXCEPTION_STACK_OVERFLOW"); break;
		case EXCEPTION_INVALID_DISPOSITION:
			printf_debug("EXCEPTION_INVALID_DISPOSITION"); break;
		case EXCEPTION_GUARD_PAGE:
			printf_debug("EXCEPTION_GUARD_PAGE"); break;
		case EXCEPTION_INVALID_HANDLE:
			printf_debug("EXCEPTION_INVALID_HANDLE"); break;
		case 0xe06d7363:
			printf_debug("C++ Exception"); break;
		//case EXCEPTION_POSSIBLE_DEADLOCK:
		//	printf_debug("EXCEPTION_POSSIBLE_DEADLOCK"); break;
		default:
			printf_debug("EXCEPTION_WTF");
	}

	printf_debug(")\n")
	printf_debug("\tExceptionFlags: 0x%08I32x\n", Exception->ExceptionFlags);
	printf_debug("\tExceptionRecord: 0x%016I64x\n", Exception->ExceptionRecord);
	printf_debug("\tExceptionAddress: 0x%016I64x\n", Exception->ExceptionAddress);
	printf_debug("\tNumberParameters: 0x%08I32x\n", Exception->NumberParameters);

	/* stay default, should be DEBUG_STATUS_BREAK */
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(CreateThread)(
        THIS_
        _In_ ULONG64 Handle,
        _In_ ULONG64 DataOffset,
        _In_ ULONG64 StartOffset
        )
{
	printf_debug("EventCallbacks::CreateThread(Handle=%016I64x DataOffset=%016I64X StartOffset=%016I64X)\n",
		Handle, DataOffset, StartOffset);
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(ExitThread)(
        THIS_
        _In_ ULONG ExitCode
        )
{
	printf_debug("EventCallbacks::ExitThread(ExitCode:%d)\n", ExitCode);
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
	printf_debug("EventCallbacks::CreateProcess()\n");
	printf_debug("  ImageFileHandle=0x%016I64X\n", ImageFileHandle);
	printf_debug("           Handle=0x%016I64X\n", Handle);
	printf_debug("       BaseOffset=0x%016I64X\n", BaseOffset);
	printf_debug("       ModuleName=\"%s\"\n", ModuleName);
	printf_debug("        ImageName=\"%s\"\n", ImageName);

	g_image_base = BaseOffset;
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

	//return DEBUG_STATUS_BREAK;
	return DEBUG_STATUS_GO;
}

STDMETHOD(ExitProcess)(
	THIS_
	IN ULONG ExitCode
)
{
	printf_debug("EventCallbacks::ExitProcess(ExitCode=%d)\n", ExitCode);

	b_PROCESS_EXITED = true;
	g_process_exit_code = ExitCode;

	return DEBUG_STATUS_NO_CHANGE;
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

	printf_debug("EventCallbacks::LoadModule()\n");
	printf_debug("\tloaded module:%s (image:%s) to address %I64x\n", ModuleName, ImageName, BaseOffset);

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(UnloadModule)(
        THIS_
        _In_opt_ PCSTR ImageBaseName,
        _In_ ULONG64 BaseOffset
        )
{
	vector<string> kill_list;

	printf_debug("EventCallbacks::UnloadModule()\n");
	printf_debug("\nloaded image:%s to address %I64x\n", ImageBaseName, BaseOffset);

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SystemError)(
        THIS_
        _In_ ULONG Error,
        _In_ ULONG Level
        )
{
	printf_debug("EventCallbacks::SystemError()\n");
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SessionStatus)(
		THIS_
		IN ULONG SessionStatus
		)
{
	printf_debug("EventCallbacks::SessionStatus()\n");
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus

	lastSessionStatus = SessionStatus;

	switch(SessionStatus)
	{
		case DEBUG_SESSION_END:
			printf_debug("\tDEBUG_SESSION_END\n");

			HRESULT hResult;

			ULONG exit_code;
			hResult = g_Client->GetExitCode(&exit_code);

			if(hResult == S_FALSE)
			{
				printf_debug("error getting return code, dude still running!\n");
			}
			else if(hResult == S_OK)
			{
				if(exit_code == STILL_ACTIVE)
				{
					printf_debug("STILL ACTIVE, WTF!\n");
				}

				printf_debug("passing back exit code %08I32x\n", exit_code);
				return exit_code;
			}
			else if(hResult == E_UNEXPECTED)
			{
				/* E_UNEXPECTED
					The target was not accessible, or the engine was not in a
					state where the function or method could be processed. */
				while(0);
			}
			else
			{
				printf_debug("wtf's up with GetExitCode()? it returned %X\n", hResult);
			}
			break;
		case DEBUG_SESSION_ACTIVE:
			printf_debug("\tDEBUG_SESSION_ACTIVE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE:
			printf_debug("\tDEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_DETACH:
			printf_debug("\tDEBUG_SESSION_END_SESSION_ACTIVE_DETACH\n");
			break;
		case DEBUG_SESSION_END_SESSION_PASSIVE:
			printf_debug("\tDEBUG_SESSION_END_SESSION_PASSIVE\n");
			break;
		case DEBUG_SESSION_REBOOT:
			printf_debug("\tDEBUG_SESSION_REBOOT\n");
			break;
		case DEBUG_SESSION_HIBERNATE:
			printf_debug("\tDEBUG_SESSION_HIBERNATE\n");
			break;
		case DEBUG_SESSION_FAILURE:
			printf_debug("\tDEBUG_SESSION_FAILURE\n");
			break;
		default:
			printf_debug("\tDEBUG_SESSION_WTF: %d\n", SessionStatus);
	}

	return S_OK;
}

STDMETHOD(ChangeDebuggeeState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
{
	printf_debug("EventCallbacks::ChangeDebuggeeState()\n");
	if(Flags & DEBUG_CDS_REGISTERS)
		printf_debug("\tDEBUG_CDS_REGISTERS\n");
	if(Flags & DEBUG_CDS_DATA)
		printf_debug("\tDEBUG_CDS_DATA\n");
	if(Flags & DEBUG_CDS_REFRESH)
		printf_debug("\tDEBUG_CDS_REFRESH\n");

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
	printf_debug("EventCallbacks::ChangeEngineState(0x%08X)\n", Flags);

	if(Flags & DEBUG_CES_CURRENT_THREAD) {
		if(Argument == DEBUG_ANY_ID)
			strcpy(buf, "TID:DEBUG_ANY_ID");
		else
			sprintf(buf, "TID:%lld", Argument);
		printf_debug("\tDEBUG_CES_CURRENT_THREAD (%s)\n", buf);
	}
	if(Flags & DEBUG_CES_EFFECTIVE_PROCESSOR)
		printf_debug("\tDEBUG_CES_EFFECTIVE_PROCESSOR\n");
	if(Flags & DEBUG_CES_BREAKPOINTS)
		printf_debug("\tDEBUG_CES_BREAKPOINTS \"One or more breakpoints have changed.\"\n");
	if(Flags & DEBUG_CES_CODE_LEVEL)
		printf_debug("\tDEBUG_CES_CODE_LEVEL\n");
	if(Flags & DEBUG_CES_EXECUTION_STATUS) {
		status_to_str(Argument, buf);
		printf_debug("\tDEBUG_CES_EXECUTION_STATUS (%s)\n", buf);
	}
	if(Flags & DEBUG_CES_SYSTEMS)
		printf_debug("\tDEBUG_CES_SYSTEMS\n");
	if(Flags & DEBUG_CES_ENGINE_OPTIONS)
		printf_debug("\tDEBUG_CES_ENGINE_OPTIONS\n");
	if(Flags & DEBUG_CES_LOG_FILE)
		printf_debug("\tDEBUG_CES_LOG_FILE\n");
	if(Flags & DEBUG_CES_RADIX)
		printf_debug("\tDEBUG_CES_RADIX\n");
	if(Flags & DEBUG_CES_EVENT_FILTERS)
		printf_debug("\tDEBUG_CES_EVENT_FILTERS\n");
	if(Flags & DEBUG_CES_PROCESS_OPTIONS)
		printf_debug("\tDEBUG_CES_PROCESS_OPTIONS\n");
	if(Flags & DEBUG_CES_EXTENSIONS)
		printf_debug("\tDEBUG_CES_EXTENSIONS\n");
	if(Flags & DEBUG_CES_ASSEMBLY_OPTIONS)
		printf_debug("\tDEBUG_CES_ASSEMBLY_OPTIONS\n");
	if(Flags & DEBUG_CES_EXPRESSION_SYNTAX)
		printf_debug("\tDEBUG_CES_EXPRESSION_SYNTAX\n");
	if(Flags & DEBUG_CES_TEXT_REPLACEMENTS)
		printf_debug("\tDEBUG_CES_TEXT_REPLACEMENTS\n");

	// The return value is ignored by the engine unless it indicates a remote procedure call error;
	// in this case the client, with which this IDebugEventCallbacks object is registered, is disabled.
	return 0;
}

// Symbol state has changed.
STDMETHOD(ChangeSymbolState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
		)
{
	printf_debug("EventCallbacks::ChangeSymbolState()\n");

	if(Flags & DEBUG_CSS_LOADS)
		printf_debug("\tDEBUG_CSS_LOADS\n");
	if(Flags & DEBUG_CSS_UNLOADS)
		printf_debug("\tDEBUG_CSS_UNLOADS\n");
	if(Flags & DEBUG_CSS_SCOPE)
		printf_debug("\tDEBUG_CSS_SCOPE\n");
	if(Flags & DEBUG_CSS_PATHS)
		printf_debug("\tDEBUG_CSS_PATHS\n");
	if(Flags & DEBUG_CSS_SYMBOL_OPTIONS)
		printf_debug("\tDEBUG_CSS_SYMBOL_OPTIONS\n");
	if(Flags & DEBUG_CSS_TYPE_OPTIONS)
		printf_debug("\tDEBUG_CSS_TYPE_OPTIONS\n");
	if(Flags & DEBUG_CSS_COLLAPSE_CHILDREN)
		printf_debug("\tDEBUG_CSS_COLLAPSE_CHILDREN\n");

	return DEBUG_STATUS_NO_CHANGE;
}

}; // class EventCallbacks

EventCallbacks g_EventCb;

/*****************************************************************************/
/* MISC UTILITIES */
/*****************************************************************************/

int wait(int timeout)
{
	// clear state that event listeners capture
	g_last_breakpoint = 0;
	memset(&g_last_exception64, '\0', sizeof(g_last_exception64));

	// block
	printf_debug("WaitForEvent(timeout=%d)\n", timeout);
	HRESULT hResult = g_Control->WaitForEvent(
		0, /* flags */
		timeout /* timeout (ms) (INFINITE == eat events until "break" event); */
	);
	printf_debug("WaitForEvent() returned %08I32x ", hResult);

	if(hResult == S_OK) {
		printf_debug("S_OK (successful)\n");
		return 0;
	}

	if(hResult == S_FALSE) {
		printf_debug("S_FALSE (timeout expired)\n");
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_PENDING) {
		printf_debug("E_PENDING (exit interrupt issued, target unavailable)\n");
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_UNEXPECTED) { /* 8000FFFF */
		printf_debug("E_UNEXPECTED (outstanding input request, or no targets generate events)\n");
		if(lastSessionStatus == DEBUG_SESSION_END) {
			printf_debug("but ok since last session status update was DEBUG_SESSION_END\n");
			return 0;
		}
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_FAIL) {
		printf_debug("E_FAIL (engine already waiting for event)\n");
		return ERROR_UNSPECIFIED;
	}

	printf_debug("(unknown)\n");

	return ERROR_UNSPECIFIED;
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
	int rc = ERROR_UNSPECIFIED;
	ULONG a, b;
	HRESULT hr;

	if(g_Objects->GetTotalNumberThreads(&a, &b) != S_OK) {
		printf_debug("ERROR: GetTotalNumberThreads()\n");
		goto cleanup;
	}

	printf_debug("number threads: %d\n", a);
	printf_debug("total threads: %d\n", b);

	if(g_Objects->GetCurrentThreadId(&a) != S_OK) {
		printf_debug("ERROR: GetCurrentThread()\n");
		goto cleanup;
	}

	printf_debug("current thread: %d\n", a);

	printf_debug("Hello, world!\n");
	printf_debug("sizeof(ULONG)==%zd\n", sizeof(ULONG));
	printf_debug("sizeof(S_OK)==%zd S_OK==%ld\n", sizeof(S_OK), S_OK);

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int echo(char *input)
{
	printf_debug("you said: %s\n", input);
	return 0;
}

/* calls related to starting and stopping debug sessions */

EASY_CTYPES_SPEC
int process_start(char *cmdline)
{
	int rc = ERROR_UNSPECIFIED;
	HRESULT hResult;

	b_PROCESS_CREATED = false;
	b_PROCESS_EXITED = false;
	b_AT_LEAST_ONE_BREAKPOINT = false;

	lastSessionStatus = DEBUG_SESSION_FAILURE;

	printf_debug("executing command line: %s\n", cmdline);

	if(!g_Client) {
		printf_debug("ERROR: interfaces not initialized\n");
		rc = ERROR_NO_DBGENG_INTERFACES;
		goto cleanup;
	}

	if(g_Control->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK) != S_OK) {
		printf_debug("ERROR: SetEngineOptions()\n");
		rc = ERROR_DBGENG_API;
		goto cleanup;
	}

	if(g_Client->CreateProcess(0, cmdline, DEBUG_ONLY_THIS_PROCESS) != S_OK) {
		printf_debug("ERROR: creating debug process\n");
		rc = ERROR_DBGENG_API;
		goto cleanup;
	}

	/* two requirements before target is considered successful started:
		1) EventCallbacks::SessionStatus() is given DEBUG_SESSION_ACTIVE
		2) EventCallbacks::CreateProcess() occurs
	*/

	/* wait for active session */
	printf_debug("waiting for active session\n");
	for(int i=0; i<10; ++i) {
		printf_debug("wait(100)\n");
		if(wait(100) == 0) {
			printf_debug("wait succeeded\n");

			//if(lastSessionStatus != DEBUG_SESSION_ACTIVE) {
			if(0) {
				printf_debug("but lastSessionStatus isn't active\n");
			} else if(!b_PROCESS_CREATED) {
				printf_debug("but process creation callback hasn't yet happened\n");
			} else if(!b_AT_LEAST_ONE_BREAKPOINT) {
				printf_debug("but initial breakpoint hasn't yet happened\n");
			} else {
				printf_debug("all's well!\n");
				rc = 0;
				goto cleanup;
			}
		}
		else {
			printf_debug("wait failed, going again...\n");
		}

	}

	printf_debug("giving up\n");

	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int process_attach(int pid)
{
	printf_debug("attaching to process: %d\n", pid);

	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	if(g_Client->AttachProcess(0, pid, 0) != S_OK)
		return ERROR_DBGENG_API;

	/* wait for active session */
	for(int i=0; i<10; ++i) {
		if(lastSessionStatus == DEBUG_SESSION_ACTIVE && b_PROCESS_CREATED) {
			printf_debug("process created!\n");
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
	int rc = ERROR_UNSPECIFIED;
	if(g_Client->TerminateProcesses() != S_OK) {
		printf_debug("ERROR: TerminateCurrentProcess() failed\n");
		goto cleanup;
	}
	else {
		printf_debug("TerminateCurrentProcess() succeeded!\n");
	}
	rc = 0;
	cleanup:
	return rc;
}

/* calls related to execution control */

EASY_CTYPES_SPEC
int break_into(void)
{
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE) != S_OK) {
		printf_debug("ERROR: SetInterrupt() failed\n");
		goto cleanup;
	}
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int go(void)
{
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK) {
		printf_debug("ERROR: SetExecutionStatus(GO) failed\n");
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
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK) {
		printf_debug("ERROR: SetExecutionStatus(STEP_INTO) failed\n");
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
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK) {
		printf_debug("ERROR: SetExecutionStatus(STEP_OVER) failed\n");
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

	/* breakpoint is not actually written until continue/go, but we need feedback
		immediate! so try to read/write to mem */

	uint8_t data[1];
	ULONG bytes_read;
	if(g_Data->ReadVirtual(addr, data, 1, &bytes_read) != S_OK) {
		printf_debug("ERROR: ReadVirtual(0x%I64X) during breakpoint precheck\n", addr);
		return ERROR_UNSPECIFIED;
	}

	if(g_Data->WriteVirtual(addr, data, 1, NULL) != S_OK) {
		printf_debug("ERROR: WriteVirtual(0x%I64X) during breakpoint precheck\n", addr);
		return ERROR_UNSPECIFIED;
	}

	if(g_Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &pidb) != S_OK) {
		printf_debug("ERROR: AddBreakpoint failed\n");
		return ERROR_DBGENG_API;
	}

	/* these never fail, even on bad addresses */
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
	int rc = ERROR_UNSPECIFIED;
	ULONG bytes_read;

	HRESULT hr = g_Data->ReadVirtual(addr, result, length, &bytes_read);
	if(hr != S_OK) {
		printf_debug("ERROR: ReadVirtual(0x%I64X, 0x%x) returned 0x%X\n",
			addr, length, hr);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int mem_write(uint64_t addr, uint8_t *data, uint32_t len)
{
	int rc = ERROR_UNSPECIFIED;

	if(g_Data->WriteVirtual(addr, data, len, NULL) != S_OK) {
		printf_debug("ERROR: WriteVirtual()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int module_num(int *num)
{
	ULONG n_loaded, n_unloaded;
	HRESULT hr;

	hr = g_Symbols->GetNumberModules(&n_loaded, &n_unloaded);
	if(hr != S_OK) {
		printf_debug("ERROR: GetNumberModules() returned 0x%X\n", hr);
		return ERROR_UNSPECIFIED;
	}

	*num = n_loaded;
	return 0;
}

EASY_CTYPES_SPEC
int module_get(int index, char *image, uint64_t *addr)
{
	int n_loaded;
	if(module_num(&n_loaded) != S_OK)
		return ERROR_UNSPECIFIED;

	if(index < 0 || index >= n_loaded) {
		printf_debug("ERROR: module_get(), index %d is negative or >= %d\n", index, n_loaded);
		return ERROR_UNSPECIFIED;
	}

	ULONG64 base;
	if(g_Symbols->GetModuleByIndex(index, &base) != S_OK) {
		printf_debug("ERROR: GetModuleByIndex()\n");
		return ERROR_UNSPECIFIED;
	}
	printf_debug("index: %d of %d\n", index, n_loaded);
	printf_debug("base: 0x%016I64X\n", base);

	char image_name[1024]; // full path, when available, like "C:\WINDOWS\System32\KERNEL32.DLL"
	char module_name[1024]; // path and extension stripped, like "KERNEL32"
	char loaded_image_name[1024]; // '\0' in my experience :/
	if(g_Symbols->GetModuleNames(index, 0,
		image_name, 1024, NULL,
		module_name, 1024, NULL,
		loaded_image_name, 1024, NULL) != S_OK) {
			printf_debug("ERROR: GetModuleNames()\n");
			return ERROR_UNSPECIFIED;
		}
	printf_debug("image_name: %s\n", image_name);
	printf_debug("module_name: %s\n", module_name);
	printf_debug("loaded_image_name: %s\n", loaded_image_name);

	if(image)
		strcpy(image, image_name);
	if(addr)
		*addr = base;
	return 0;
}

EASY_CTYPES_SPEC
int reg_read(char *name, uint64_t *result)
{
	int rc = ERROR_UNSPECIFIED;

	ULONG reg_index;
	DEBUG_VALUE dv;

	if(g_Registers->GetIndexByName(name, &reg_index) != S_OK) {
		printf_debug("ERROR: GetIndexByName(\"%s\")\n", name);
		goto cleanup;
	}

	if(g_Registers->GetValue(reg_index, &dv) != S_OK) {
		printf_debug("ERROR: GetValue()\n");
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
		printf_debug("ERROR: GetIndexByName(\"%s\")\n", name);
		goto cleanup;
	}
	printf_debug("The value of register %s is %d\n", name, reg_index);

	dv.I64 = value;
	dv.Type = DEBUG_VALUE_INT64;
	HRESULT hr = g_Registers->SetValue(reg_index, &dv);
	if(hr != S_OK) {
		printf_debug("ERROR: SetValue() returned %08X\n", hr);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int reg_count(int *count)
{
	ULONG ulcount;
	if(g_Registers->GetNumberRegisters(&ulcount) != S_OK) {
		printf_debug("ERROR: GetNumberRegisters()\n");
		return ERROR_UNSPECIFIED;
	}
	*count = ulcount;
	return 0;
}

EASY_CTYPES_SPEC
int reg_name(int idx, char *name)
{
	HRESULT rc;

	ULONG len;
	DEBUG_REGISTER_DESCRIPTION descr;

	rc = g_Registers->GetDescription(idx, name, 256, &len, &descr);
	if(rc != S_OK) {
		printf_debug("ERROR: GetDescription() returned %08X\n", rc);
		return ERROR_UNSPECIFIED;
	}

	return 0;
}

EASY_CTYPES_SPEC
int reg_width(char *name, int *width)
{
	ULONG regidx;
	if(g_Registers->GetIndexByName(name, &regidx) != S_OK) {
		printf_debug("ERROR: GetIndexByName()\n");
		return ERROR_UNSPECIFIED;
	}

	ULONG len;
	char tmp[256];
	DEBUG_REGISTER_DESCRIPTION descr;
	int rc = g_Registers->GetDescription(regidx, tmp, 256, &len, &descr);
	if(rc != S_OK) {
		printf_debug("ERROR: GetDescription() returned %08X\n", rc);
		return ERROR_UNSPECIFIED;
	}

	switch(descr.Type) {
		case DEBUG_VALUE_INT8: *width = 8; return 0;
		case DEBUG_VALUE_INT16: *width = 16; return 0;
		case DEBUG_VALUE_INT32: *width = 32; return 0;
		case DEBUG_VALUE_INT64: *width = 64; return 0;
		case DEBUG_VALUE_FLOAT32: *width = 32; return 0;
		case DEBUG_VALUE_FLOAT64: *width = 64; return 0;
		case DEBUG_VALUE_FLOAT80: *width = 80; return 0;
		case DEBUG_VALUE_FLOAT128: *width = 128; return 0;
		case DEBUG_VALUE_VECTOR64: *width = 64; return 0;
		case DEBUG_VALUE_VECTOR128: *width = 128; return 0;
		default:
			return ERROR_UNSPECIFIED;
	}
}

EASY_CTYPES_SPEC
int get_exec_status(unsigned long *status)
{
	*status = ERROR_UNSPECIFIED;
	if(g_Control->GetExecutionStatus(status) != S_OK) {
		printf_debug("ERROR: GetExecutionStatus() failed\n");
		return ERROR_UNSPECIFIED;
	}

	char buf[64];
	status_to_str(*status, buf);
	printf_debug("get_exec_status() returning %s\n", buf);
	return 0;
}

EASY_CTYPES_SPEC
int get_exit_code(unsigned long *code)
{
	if(!b_PROCESS_EXITED) {
		printf_debug("ERROR: attempt to retrieve exit code of a non-exited process\n");
		return ERROR_UNSPECIFIED;
	}

	*code = g_process_exit_code;
	return 0;
}

/* calls related to threads */

EASY_CTYPES_SPEC
int set_current_thread(ULONG id)
{
	int rc = ERROR_UNSPECIFIED;

	if(g_Objects->SetCurrentThreadId(id) != S_OK) {
		printf_debug("ERROR: SetCurrentThreadId()\n");
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
		printf_debug("ERROR: GetCurrentThread()\n");
		return ERROR_UNSPECIFIED;
	}
	return tid;
}

EASY_CTYPES_SPEC
int get_number_threads(void)
{
	ULONG Total, LargestProcess;
	if(g_Objects->GetTotalNumberThreads(&Total, &LargestProcess) != S_OK) {
		printf_debug("ERROR: GetTotalNumberThreads()\n");
		return ERROR_UNSPECIFIED;
	}
	return Total;
}

/* misc */
EASY_CTYPES_SPEC
int get_pid(ULONG *pid)
{
	if(g_Objects->GetCurrentProcessSystemId(pid) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* current processor type (may switch between 64 and 32 in WoW64) */
EASY_CTYPES_SPEC
int get_executing_processor_type(ULONG *proc_type)
{
	if(g_Control->GetExecutingProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* processor the target image uses */
EASY_CTYPES_SPEC
int get_effective_processor_type(ULONG *proc_type)
{
	if(g_Control->GetEffectiveProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* physical processor on the machine running the target */
EASY_CTYPES_SPEC
int get_actual_processor_type(ULONG *proc_type)
{
	if(g_Control->GetEffectiveProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

EASY_CTYPES_SPEC
int get_image_base(ULONGLONG *base)
{
	*base = g_image_base;
	return 0;
}

EASY_CTYPES_SPEC
int get_exception_record64(EXCEPTION_RECORD64 *result)
{
	*result = g_last_exception64;
	return 0;
}

EASY_CTYPES_SPEC
int get_last_breakpoint_address(uint64_t *addr)
{
	*addr = g_last_breakpoint;
	return 0;
}

/*****************************************************************************/
/* INITIALIZATION, ENTRYPOINT */
/*****************************************************************************/

EASY_CTYPES_SPEC
int setup(void)
{
	int rc = ERROR_UNSPECIFIED;
	HRESULT hResult;

	printf_debug("setup()\n");

	hResult = DebugCreate(__uuidof(IDebugClient5), (void **)&g_Client);
	if(hResult != S_OK)
	{
		printf_debug("ERROR: getting IDebugClient5\n");
		goto cleanup;
	}

	if ((hResult = g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&g_Data)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugRegisters), (void**)&g_Registers)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugSymbols), (void**)&g_Symbols)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&g_Objects)) != S_OK)
	{
		printf_debug("ERROR: getting client debugging interface\n");
		goto cleanup;
	}

	if ((hResult = g_Client->SetEventCallbacks(&g_EventCb)) != S_OK)
	{
		printf_debug("ERROR: registering event callbacks\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int teardown(void)
{
	printf_debug("teardown()\n");

	if (g_Control != NULL) {
		g_Control->Release();
		g_Control = NULL;
	}

	if (g_Data != NULL) {
		g_Data->Release();
		g_Data = NULL;
	}

	if (g_Registers != NULL) {
		g_Registers->Release();
		g_Registers = NULL;
	}

	if (g_Symbols != NULL) {
		g_Symbols->Release();
		g_Symbols = NULL;
	}

	if (g_Objects != NULL) {
		g_Objects->Release();
		g_Objects = NULL;
	}

	if (g_Client != NULL) {
		g_Client->EndSession(DEBUG_END_PASSIVE);
		g_Client->Release();
		g_Client = NULL;
	}

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch(fdwReason) {
		case DLL_PROCESS_DETACH:
			printf_debug("DLL_PROCESS_DETACH\n");
			teardown();
			break;

		case DLL_PROCESS_ATTACH:
			printf_debug("DLL_PROCESS_ATTACH\n");
			/* do NOT initialize here, user should call setup() */
			/* SEE: https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain */
			break;

		case DLL_THREAD_ATTACH:
			printf_debug("DLL_THREAD_ATTACH\n");
			break;

		case DLL_THREAD_DETACH:
			printf_debug("DLL_THREAD_DETACH\n");
			break;

		default:
			printf_debug("unknown fdwReason: %d\n", fdwReason);
			break;
	}

	return true;
}

