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
int client_setup(char *errmsg);
int client_teardown(void);

/*****************************************************************************/
/* DEBUG REPORTING */
/*****************************************************************************/

void report(char *buf_remote, const char *fmt...)
{
	va_list args;
	va_start(args, fmt);

	bool output = false;
	//output = true;

	if(buf_remote==NULL && output==false)
		return;

	char buf_local[4096];
	char *buf = (buf_remote == NULL) ? buf_local : buf_remote;
	vsprintf(buf, fmt, args);

	if(output) {
		OutputDebugString(buf);
		printf(buf);
	}

	va_end(args);
}

/*****************************************************************************/
/* EVENT CALLBACKS */
/*****************************************************************************/

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugeventcallbacks

class EventCallbacks : public DebugBaseEventCallbacks
{
	public:

STDMETHOD_(ULONG,AddRef)(THIS)
{
	report(NULL, "EventCallbacks::AddRef()\n");
	return 1;
}

STDMETHOD_(ULONG,Release)(THIS)
{
	report(NULL, "EventCallbacks::Release()\n");
	return 0;
}

STDMETHOD(GetInterestMask(THIS_ OUT PULONG Mask))
{
	report(NULL, "EventCallbacks::GetInterestMask()\n");

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
	report(NULL, "EventCallbacks::Breakpoint()\n");

	ULONG64 addr;
	if(Bp->GetOffset(&addr) == S_OK) {
		report(NULL, "\taddress: 0x%016I64x\n", addr);
		g_last_breakpoint = addr;
	}
	else
		report(NULL, "\t(failed to get address)\n");

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(Exception)(
	THIS_ IN PEXCEPTION_RECORD64 Exception,
	IN ULONG FirstChance
)
{
	// remember, at this point, the debugger status is at DEBUG_STATUS_BREAK
	report(NULL, "EventCallbacks::Exception()\n");
	g_last_exception64 = *Exception;

	report(NULL, "\tFirstChance: 0x%08I32x\n", Exception->NumberParameters);
	report(NULL, "\tEXCEPTION_RECORD64:\n"
			"\tExceptionCode: 0x%I32x (",
			Exception->ExceptionCode);

	switch(Exception->ExceptionCode) {
		case EXCEPTION_ACCESS_VIOLATION:
			report(NULL, "EXCEPTION_ACCESS_VIOLATION"); break;
		case EXCEPTION_DATATYPE_MISALIGNMENT:
			report(NULL, "EXCEPTION_DATATYPE_MISALIGNMENT"); break;
		case EXCEPTION_BREAKPOINT:
			report(NULL, "EXCEPTION_BREAKPOINT");
			b_AT_LEAST_ONE_BREAKPOINT = true;
			break;
		case EXCEPTION_SINGLE_STEP:
			report(NULL, "EXCEPTION_SINGLE_STEP"); break;
		case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
			report(NULL, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"); break;
		case EXCEPTION_FLT_DENORMAL_OPERAND:
			report(NULL, "EXCEPTION_FLT_DENORMAL_OPERAND"); break;
		case EXCEPTION_FLT_DIVIDE_BY_ZERO:
			report(NULL, "EXCEPTION_FLT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_FLT_INEXACT_RESULT:
			report(NULL, "EXCEPTION_FLT_INEXACT_RESULT"); break;
		case EXCEPTION_FLT_INVALID_OPERATION:
			report(NULL, "EXCEPTION_FLT_INVALID_OPERATION"); break;
		case EXCEPTION_FLT_OVERFLOW:
			report(NULL, "EXCEPTION_FLT_OVERFLOW"); break;
		case EXCEPTION_FLT_STACK_CHECK:
			report(NULL, "EXCEPTION_FLT_STACK_CHECK"); break;
		case EXCEPTION_FLT_UNDERFLOW:
			report(NULL, "EXCEPTION_FLT_UNDERFLOW"); break;
		case EXCEPTION_INT_DIVIDE_BY_ZERO:
			report(NULL, "EXCEPTION_INT_DIVIDE_BY_ZERO"); break;
		case EXCEPTION_INT_OVERFLOW:
			report(NULL, "EXCEPTION_INT_OVERFLOW"); break;
		case EXCEPTION_PRIV_INSTRUCTION:
			report(NULL, "EXCEPTION_PRIV_INSTRUCTION"); break;
		case EXCEPTION_IN_PAGE_ERROR:
			report(NULL, "EXCEPTION_IN_PAGE_ERROR"); break;
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			report(NULL, "EXCEPTION_ILLEGAL_INSTRUCTION"); break;
		case EXCEPTION_NONCONTINUABLE_EXCEPTION:
			report(NULL, "EXCEPTION_NONCONTINUABLE_EXCEPTION"); break;
		case EXCEPTION_STACK_OVERFLOW:
			report(NULL, "EXCEPTION_STACK_OVERFLOW"); break;
		case EXCEPTION_INVALID_DISPOSITION:
			report(NULL, "EXCEPTION_INVALID_DISPOSITION"); break;
		case EXCEPTION_GUARD_PAGE:
			report(NULL, "EXCEPTION_GUARD_PAGE"); break;
		case EXCEPTION_INVALID_HANDLE:
			report(NULL, "EXCEPTION_INVALID_HANDLE"); break;
		case 0xe06d7363:
			report(NULL, "C++ Exception"); break;
		//case EXCEPTION_POSSIBLE_DEADLOCK:
		//	report(NULL, "EXCEPTION_POSSIBLE_DEADLOCK"); break;
		default:
			report(NULL, "EXCEPTION_WTF");
	}

	report(NULL, ")\n");
	report(NULL, "\tExceptionFlags: 0x%08I32x\n", Exception->ExceptionFlags);
	report(NULL, "\tExceptionRecord: 0x%016I64x\n", Exception->ExceptionRecord);
	report(NULL, "\tExceptionAddress: 0x%016I64x\n", Exception->ExceptionAddress);
	report(NULL, "\tNumberParameters: 0x%08I32x\n", Exception->NumberParameters);

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
	report(NULL, "EventCallbacks::CreateThread(Handle=%016I64x DataOffset=%016I64X StartOffset=%016I64X)\n",
		Handle, DataOffset, StartOffset);
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(ExitThread)(
        THIS_
        _In_ ULONG ExitCode
        )
{
	report(NULL, "EventCallbacks::ExitThread(ExitCode:%d)\n", ExitCode);
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
	report(NULL, "EventCallbacks::CreateProcess()\n");
	report(NULL, "  ImageFileHandle=0x%016I64X\n", ImageFileHandle);
	report(NULL, "           Handle=0x%016I64X\n", Handle);
	report(NULL, "       BaseOffset=0x%016I64X\n", BaseOffset);
	report(NULL, "       ModuleName=\"%s\"\n", ModuleName);
	report(NULL, "        ImageName=\"%s\"\n", ImageName);

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
	report(NULL, "EventCallbacks::ExitProcess(ExitCode=%d)\n", ExitCode);

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

	report(NULL, "EventCallbacks::LoadModule()\n");
	report(NULL, "\tloaded module:%s (image:%s) to address %I64x\n", ModuleName, ImageName, BaseOffset);

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(UnloadModule)(
        THIS_
        _In_opt_ PCSTR ImageBaseName,
        _In_ ULONG64 BaseOffset
        )
{
	report(NULL, "EventCallbacks::UnloadModule()\n");
	report(NULL, "\nloaded image:%s to address %I64x\n", ImageBaseName, BaseOffset);

	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SystemError)(
        THIS_
        _In_ ULONG Error,
        _In_ ULONG Level
        )
{
	report(NULL, "EventCallbacks::SystemError()\n");
	return DEBUG_STATUS_NO_CHANGE;
}

STDMETHOD(SessionStatus)(
		THIS_
		IN ULONG SessionStatus
		)
{
	report(NULL, "EventCallbacks::SessionStatus()\n");
	// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus

	lastSessionStatus = SessionStatus;

	switch(SessionStatus)
	{
		case DEBUG_SESSION_END:
			report(NULL, "\tDEBUG_SESSION_END\n");

			HRESULT hResult;

			ULONG exit_code;
			hResult = g_Client->GetExitCode(&exit_code);

			if(hResult == S_FALSE)
			{
				report(NULL, "error getting return code, dude still running!\n");
			}
			else if(hResult == S_OK)
			{
				if(exit_code == STILL_ACTIVE)
				{
					report(NULL, "STILL ACTIVE, WTF!\n");
				}

				report(NULL, "passing back exit code %08I32x\n", exit_code);
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
				report(NULL, "wtf's up with GetExitCode()? it returned %X\n", hResult);
			}
			break;
		case DEBUG_SESSION_ACTIVE:
			report(NULL, "\tDEBUG_SESSION_ACTIVE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE:
			report(NULL, "\tDEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE\n");
			break;
		case DEBUG_SESSION_END_SESSION_ACTIVE_DETACH:
			report(NULL, "\tDEBUG_SESSION_END_SESSION_ACTIVE_DETACH\n");
			break;
		case DEBUG_SESSION_END_SESSION_PASSIVE:
			report(NULL, "\tDEBUG_SESSION_END_SESSION_PASSIVE\n");
			break;
		case DEBUG_SESSION_REBOOT:
			report(NULL, "\tDEBUG_SESSION_REBOOT\n");
			break;
		case DEBUG_SESSION_HIBERNATE:
			report(NULL, "\tDEBUG_SESSION_HIBERNATE\n");
			break;
		case DEBUG_SESSION_FAILURE:
			report(NULL, "\tDEBUG_SESSION_FAILURE\n");
			break;
		default:
			report(NULL, "\tDEBUG_SESSION_WTF: %d\n", SessionStatus);
	}

	return S_OK;
}

STDMETHOD(ChangeDebuggeeState)(
        THIS_
        _In_ ULONG Flags,
        _In_ ULONG64 Argument
        )
{
	report(NULL, "EventCallbacks::ChangeDebuggeeState()\n");
	if(Flags & DEBUG_CDS_REGISTERS)
		report(NULL, "\tDEBUG_CDS_REGISTERS\n");
	if(Flags & DEBUG_CDS_DATA)
		report(NULL, "\tDEBUG_CDS_DATA\n");
	if(Flags & DEBUG_CDS_REFRESH)
		report(NULL, "\tDEBUG_CDS_REFRESH\n");

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
	report(NULL, "EventCallbacks::ChangeEngineState(0x%08X)\n", Flags);

	if(Flags & DEBUG_CES_CURRENT_THREAD) {
		if(Argument == DEBUG_ANY_ID)
			strcpy(buf, "TID:DEBUG_ANY_ID");
		else
			sprintf(buf, "TID:%lld", Argument);
		report(NULL, "\tDEBUG_CES_CURRENT_THREAD (%s)\n", buf);
	}
	if(Flags & DEBUG_CES_EFFECTIVE_PROCESSOR)
		report(NULL, "\tDEBUG_CES_EFFECTIVE_PROCESSOR\n");
	if(Flags & DEBUG_CES_BREAKPOINTS)
		report(NULL, "\tDEBUG_CES_BREAKPOINTS \"One or more breakpoints have changed.\"\n");
	if(Flags & DEBUG_CES_CODE_LEVEL)
		report(NULL, "\tDEBUG_CES_CODE_LEVEL\n");
	if(Flags & DEBUG_CES_EXECUTION_STATUS) {
		status_to_str(Argument, buf);
		report(NULL, "\tDEBUG_CES_EXECUTION_STATUS (%s)\n", buf);
	}
	if(Flags & DEBUG_CES_SYSTEMS)
		report(NULL, "\tDEBUG_CES_SYSTEMS\n");
	if(Flags & DEBUG_CES_ENGINE_OPTIONS)
		report(NULL, "\tDEBUG_CES_ENGINE_OPTIONS\n");
	if(Flags & DEBUG_CES_LOG_FILE)
		report(NULL, "\tDEBUG_CES_LOG_FILE\n");
	if(Flags & DEBUG_CES_RADIX)
		report(NULL, "\tDEBUG_CES_RADIX\n");
	if(Flags & DEBUG_CES_EVENT_FILTERS)
		report(NULL, "\tDEBUG_CES_EVENT_FILTERS\n");
	if(Flags & DEBUG_CES_PROCESS_OPTIONS)
		report(NULL, "\tDEBUG_CES_PROCESS_OPTIONS\n");
	if(Flags & DEBUG_CES_EXTENSIONS)
		report(NULL, "\tDEBUG_CES_EXTENSIONS\n");
	if(Flags & DEBUG_CES_ASSEMBLY_OPTIONS)
		report(NULL, "\tDEBUG_CES_ASSEMBLY_OPTIONS\n");
	if(Flags & DEBUG_CES_EXPRESSION_SYNTAX)
		report(NULL, "\tDEBUG_CES_EXPRESSION_SYNTAX\n");
	if(Flags & DEBUG_CES_TEXT_REPLACEMENTS)
		report(NULL, "\tDEBUG_CES_TEXT_REPLACEMENTS\n");

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
	report(NULL, "EventCallbacks::ChangeSymbolState()\n");

	if(Flags & DEBUG_CSS_LOADS)
		report(NULL, "\tDEBUG_CSS_LOADS\n");
	if(Flags & DEBUG_CSS_UNLOADS)
		report(NULL, "\tDEBUG_CSS_UNLOADS\n");
	if(Flags & DEBUG_CSS_SCOPE)
		report(NULL, "\tDEBUG_CSS_SCOPE\n");
	if(Flags & DEBUG_CSS_PATHS)
		report(NULL, "\tDEBUG_CSS_PATHS\n");
	if(Flags & DEBUG_CSS_SYMBOL_OPTIONS)
		report(NULL, "\tDEBUG_CSS_SYMBOL_OPTIONS\n");
	if(Flags & DEBUG_CSS_TYPE_OPTIONS)
		report(NULL, "\tDEBUG_CSS_TYPE_OPTIONS\n");
	if(Flags & DEBUG_CSS_COLLAPSE_CHILDREN)
		report(NULL, "\tDEBUG_CSS_COLLAPSE_CHILDREN\n");

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
	report(NULL, "WaitForEvent(timeout=%d)\n", timeout);
	HRESULT hResult = g_Control->WaitForEvent(
		0, /* flags */
		timeout /* timeout (ms) (INFINITE == eat events until "break" event); */
	);
	report(NULL, "WaitForEvent() returned %08I32x ", hResult);

	if(hResult == S_OK) {
		report(NULL, "S_OK (successful)\n");
		return 0;
	}

	if(hResult == S_FALSE) {
		report(NULL, "S_FALSE (timeout expired)\n");
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_PENDING) {
		report(NULL, "E_PENDING (exit interrupt issued, target unavailable)\n");
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_UNEXPECTED) { /* 8000FFFF */
		report(NULL, "E_UNEXPECTED (outstanding input request, or no targets generate events)\n");
		if(lastSessionStatus == DEBUG_SESSION_END) {
			report(NULL, "but ok since last session status update was DEBUG_SESSION_END\n");
			return 0;
		}
		return ERROR_UNSPECIFIED;
	}

	if(hResult == E_FAIL) {
		report(NULL, "E_FAIL (engine already waiting for event)\n");
		return ERROR_UNSPECIFIED;
	}

	report(NULL, "(unknown)\n");

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

/* calls related to starting and stopping debug sessions */

EASY_CTYPES_SPEC
int process_start(char *cmdline, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	HRESULT hResult;

	b_PROCESS_CREATED = false;
	b_PROCESS_EXITED = false;
	b_AT_LEAST_ONE_BREAKPOINT = false;

	lastSessionStatus = DEBUG_SESSION_FAILURE;

	report(NULL, "executing command line: %s\n", cmdline);

	/* end any current sessions */
	if(g_Client) {
		report(NULL, "WARNING: client/session already active, attempting shutdown\n");
		client_teardown();
	}

	if(g_Client) {
		report(errmsg, "ERROR: unable to end current client/session\n");
		goto cleanup;
	}

	/* start new session */
	if(client_setup(errmsg)) {
		report(errmsg, "ERROR: client_setup() initializing client/session\n");
		// client_setup() set errmsg
		goto cleanup;
	}

	/* set engine, create process */
	hResult = g_Control->SetEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK);
	if(hResult != S_OK) {
		report(errmsg, "ERROR: SetEngineOptions() returned 0x%08X\n", hResult);
		rc = ERROR_DBGENG_API;
		goto cleanup;
	}

	hResult = g_Client->CreateProcess(0, cmdline, DEBUG_ONLY_THIS_PROCESS);
	if(hResult != S_OK) {
		report(errmsg, "ERROR: CreateProcess() returned 0x%08X, cmdline: %s\n", hResult, cmdline);
		rc = ERROR_DBGENG_API;
		goto cleanup;
	}

	/* two requirements before target is considered successful started:
		1) EventCallbacks::SessionStatus() is given DEBUG_SESSION_ACTIVE
		2) EventCallbacks::CreateProcess() occurs
	*/

	/* wait for active session */
	report(NULL, "waiting for active session\n");
	for(int i=0; i<10; ++i) {
		report(NULL, "wait(100)\n");
		if(wait(100) == 0) {
			report(NULL, "wait succeeded\n");

			//if(lastSessionStatus != DEBUG_SESSION_ACTIVE) {
			if(0) {
				report(NULL, "but lastSessionStatus isn't active\n");
			} else if(!b_PROCESS_CREATED) {
				report(NULL, "but process creation callback hasn't yet happened\n");
			} else if(!b_AT_LEAST_ONE_BREAKPOINT) {
				report(NULL, "but initial breakpoint hasn't yet happened\n");
			} else {
				report(NULL, "all's well!\n");
				rc = 0;
				goto cleanup;
			}
		}
		else {
			report(NULL, "wait failed, going again...\n");
		}

	}

	report(errmsg, "ERROR: gave up! returning %d\n", rc);

	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int process_attach(int pid, char *errmsg)
{
	HRESULT hResult;

	report(NULL, "attaching to process: %d\n", pid);

	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	hResult = g_Client->AttachProcess(0, pid, 0);
	if(hResult != S_OK) {
		report(errmsg, "ERROR: g_Client->AttachProcess(0, %d, 0) returned 0x%X\n", pid, hResult);
		return ERROR_DBGENG_API;
	}

	/* wait for active session */
	for(int i=0; i<10; ++i) {
		if(lastSessionStatus == DEBUG_SESSION_ACTIVE && b_PROCESS_CREATED) {
			report(NULL, "process created!\n");
			return 0;
		}

		wait(INFINITE);
	}

	report(errmsg, "ERROR: timeout waiting for active debug session\n");
	return ERROR_UNSPECIFIED;
}

EASY_CTYPES_SPEC
int process_detach(char *errmsg)
{
	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	if(g_Client->DetachProcesses())
		return ERROR_DBGENG_API;

	client_teardown();

	return 0;
}

EASY_CTYPES_SPEC
int quit(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;

	if(!g_Client)
		return ERROR_NO_DBGENG_INTERFACES;

	HRESULT hr = g_Client->TerminateProcesses();
	if(hr != S_OK) {
		report(errmsg, "ERROR: TerminateCurrentProcess() returned 0x%08X\n", hr);
		goto cleanup;
	}
	else {
		report(NULL, "TerminateCurrentProcess() succeeded!\n");
	}

	client_teardown();

	rc = 0;
	cleanup:
	return rc;
}

/* calls related to execution control */

EASY_CTYPES_SPEC
int break_into(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	HRESULT hr = g_Control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
	if(hr != S_OK) {
		report(errmsg, "ERROR: SetInterrupt() returned 0x%08X\n", hr);
		goto cleanup;
	}
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int go(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_GO) != S_OK) {
		report(errmsg, "ERROR: SetExecutionStatus(GO) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int step_into(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_INTO) != S_OK) {
		report(errmsg, "ERROR: SetExecutionStatus(STEP_INTO) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int step_over(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	if(g_Control->SetExecutionStatus(DEBUG_STATUS_STEP_OVER) != S_OK) {
		report(errmsg, "ERROR: SetExecutionStatus(STEP_OVER) failed\n");
		goto cleanup;
	}
	wait(INFINITE);
	rc = 0;
	cleanup:
	return rc;
}

/* calls related to breakpoints */

EASY_CTYPES_SPEC
int breakpoint_set(uint64_t addr, ULONG *id, char *errmsg)
{
	IDebugBreakpoint *pidb = NULL;

	/* breakpoint is not actually written until continue/go, but we need feedback
		immediate! so try to read/write to mem */

	uint8_t data[1];
	ULONG bytes_read;
	HRESULT hr = g_Data->ReadVirtual(addr, data, 1, &bytes_read);
	if(hr != S_OK) {
		report(errmsg, "ERROR: ReadVirtual(0x%I64X) returned 0x%08X during breakpoint precheck\n", addr, hr);
		return ERROR_UNSPECIFIED;
	}

	hr = g_Data->WriteVirtual(addr, data, 1, NULL);
	if(hr != S_OK) {
		report(errmsg, "ERROR: WriteVirtual(0x%I64X) returned 0x%08X during breakpoint precheck\n", addr, hr);
		return ERROR_UNSPECIFIED;
	}

	hr = g_Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &pidb);
	if(hr != S_OK) {
		report(errmsg, "ERROR: AddBreakpoint() returned 0x%08X\n", hr);
		return ERROR_DBGENG_API;
	}

	/* these never fail, even on bad addresses */
	pidb->GetId(id);
	pidb->SetOffset(addr);
	pidb->SetFlags(DEBUG_BREAKPOINT_ENABLED);

	return 0;
}

EASY_CTYPES_SPEC
int breakpoint_clear(ULONG id, char *errmsg)
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
int mem_read(uint64_t addr, uint32_t length, uint8_t *result, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	ULONG bytes_read;

	HRESULT hr = g_Data->ReadVirtual(addr, result, length, &bytes_read);
	if(hr != S_OK) {
		report(errmsg, "ERROR: ReadVirtual(0x%I64X, 0x%x) returned 0x%X\n", addr, length, hr);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int mem_write(uint64_t addr, uint8_t *data, uint32_t len, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;

	if(g_Data->WriteVirtual(addr, data, len, NULL) != S_OK) {
		report(errmsg, "ERROR: WriteVirtual()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int module_num(int *num, char *errmsg)
{
	ULONG n_loaded, n_unloaded;

	HRESULT hr = g_Symbols->GetNumberModules(&n_loaded, &n_unloaded);
	if(hr != S_OK) {
		report(errmsg, "ERROR: GetNumberModules() returned 0x%X\n", hr);
		return ERROR_UNSPECIFIED;
	}

	*num = n_loaded;
	return 0;
}

EASY_CTYPES_SPEC
int module_get(int index, char *image, uint64_t *addr, char *errmsg)
{
	int n_loaded;
	int ir = module_num(&n_loaded, errmsg);
	if(ir) {
		// module_num() has set errmsg
		return ir;
	}

	if(index < 0 || index >= n_loaded) {
		report(errmsg, "ERROR: module_get(), index %d is negative or >= %d\n", index, n_loaded);
		return ERROR_UNSPECIFIED;
	}

	ULONG64 base;
	if(g_Symbols->GetModuleByIndex(index, &base) != S_OK) {
		report(errmsg, "ERROR: GetModuleByIndex()\n");
		return ERROR_UNSPECIFIED;
	}
	report(NULL, "index: %d of %d\n", index, n_loaded);
	report(NULL, "base: 0x%016I64X\n", base);

	char image_name[1024]; // full path, when available, like "C:\WINDOWS\System32\KERNEL32.DLL"
	char module_name[1024]; // path and extension stripped, like "KERNEL32"
	char loaded_image_name[1024]; // '\0' in my experience :/
	if(g_Symbols->GetModuleNames(index, 0,
		image_name, 1024, NULL,
		module_name, 1024, NULL,
		loaded_image_name, 1024, NULL) != S_OK) {
			report(errmsg, "ERROR: GetModuleNames()\n");
			return ERROR_UNSPECIFIED;
		}
	report(NULL, "image_name: %s\n", image_name);
	report(NULL, "module_name: %s\n", module_name);
	report(NULL, "loaded_image_name: %s\n", loaded_image_name);

	if(image)
		strcpy(image, image_name);
	if(addr)
		*addr = base;
	return 0;
}

EASY_CTYPES_SPEC
int reg_read(char *name, uint64_t *result, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;

	ULONG reg_index;
	DEBUG_VALUE dv;

	if(g_Registers->GetIndexByName(name, &reg_index) != S_OK) {
		report(errmsg, "ERROR: GetIndexByName(\"%s\")\n", name);
		goto cleanup;
	}

	if(g_Registers->GetValue(reg_index, &dv) != S_OK) {
		report(errmsg, "ERROR: GetValue()\n");
		goto cleanup;
	}

	*result = dv.I64;

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int reg_write(char *name, uint64_t value, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;

	ULONG reg_index;
	DEBUG_VALUE dv;

	if(g_Registers->GetIndexByName(name, &reg_index) != S_OK) {
		report(errmsg, "ERROR: GetIndexByName(\"%s\")\n", name);
		goto cleanup;
	}
	report(NULL, "The value of register %s is %d\n", name, reg_index);

	dv.I64 = value;
	dv.Type = DEBUG_VALUE_INT64;
	HRESULT hr = g_Registers->SetValue(reg_index, &dv);
	if(hr != S_OK) {
		report(errmsg, "ERROR: SetValue() returned %08X\n", hr);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int reg_count(int *count, char *errmsg)
{
	ULONG ulcount;
	if(g_Registers->GetNumberRegisters(&ulcount) != S_OK) {
		report(errmsg, "ERROR: GetNumberRegisters()\n");
		return ERROR_UNSPECIFIED;
	}
	*count = ulcount;
	return 0;
}

EASY_CTYPES_SPEC
int reg_name(int idx, char *name, char *errmsg)
{
	HRESULT rc;

	ULONG len;
	DEBUG_REGISTER_DESCRIPTION descr;

	rc = g_Registers->GetDescription(idx, name, 256, &len, &descr);
	if(rc != S_OK) {
		report(errmsg, "ERROR: GetDescription() returned %08X\n", rc);
		return ERROR_UNSPECIFIED;
	}

	return 0;
}

EASY_CTYPES_SPEC
int reg_width(char *name, int *width, char *errmsg)
{
	ULONG regidx;
	if(g_Registers->GetIndexByName(name, &regidx) != S_OK) {
		report(errmsg, "ERROR: GetIndexByName()\n");
		return ERROR_UNSPECIFIED;
	}

	ULONG len;
	char tmp[256];
	DEBUG_REGISTER_DESCRIPTION descr;
	int rc = g_Registers->GetDescription(regidx, tmp, 256, &len, &descr);
	if(rc != S_OK) {
		report(errmsg, "ERROR: GetDescription() returned %08X\n", rc);
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
int get_exec_status(unsigned long *status, char *errmsg)
{
	*status = ERROR_UNSPECIFIED;
	if(g_Control->GetExecutionStatus(status) != S_OK) {
		report(errmsg, "ERROR: GetExecutionStatus() failed\n");
		return ERROR_UNSPECIFIED;
	}

	char buf[64];
	status_to_str(*status, buf);
	report(NULL, "get_exec_status() returning %s\n", buf);
	return 0;
}

EASY_CTYPES_SPEC
int get_exit_code(unsigned long *code, char *errmsg)
{
	if(!b_PROCESS_EXITED) {
		report(errmsg, "ERROR: attempt to retrieve exit code of a non-exited process\n");
		return ERROR_UNSPECIFIED;
	}

	*code = g_process_exit_code;
	return 0;
}

/* calls related to threads */

EASY_CTYPES_SPEC
int set_current_thread(ULONG id, char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;

	if(g_Objects->SetCurrentThreadId(id) != S_OK) {
		report(errmsg, "ERROR: SetCurrentThreadId()\n");
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

EASY_CTYPES_SPEC
int get_current_thread(char *errmsg)
{
	ULONG tid;
	if(g_Objects->GetCurrentThreadId(&tid) != S_OK) {
		report(errmsg, "ERROR: GetCurrentThread()\n");
		return ERROR_UNSPECIFIED;
	}
	return tid;
}

EASY_CTYPES_SPEC
int get_number_threads(char *errmsg)
{
	ULONG Total, LargestProcess;
	if(g_Objects->GetTotalNumberThreads(&Total, &LargestProcess) != S_OK) {
		report(errmsg, "ERROR: GetTotalNumberThreads()\n");
		return ERROR_UNSPECIFIED;
	}
	return Total;
}

/* misc */
EASY_CTYPES_SPEC
int get_pid(ULONG *pid, char *errmsg)
{
	if(g_Objects->GetCurrentProcessSystemId(pid) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* current processor type (may switch between 64 and 32 in WoW64) */
EASY_CTYPES_SPEC
int get_executing_processor_type(ULONG *proc_type, char *errmsg)
{
	if(g_Control->GetExecutingProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* processor the target image uses */
EASY_CTYPES_SPEC
int get_effective_processor_type(ULONG *proc_type, char *errmsg)
{
	if(g_Control->GetEffectiveProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

/* physical processor on the machine running the target */
EASY_CTYPES_SPEC
int get_actual_processor_type(ULONG *proc_type, char *errmsg)
{
	if(g_Control->GetEffectiveProcessorType(proc_type) != S_OK)
		return ERROR_UNSPECIFIED;
	return 0;
}

EASY_CTYPES_SPEC
int get_image_base(ULONGLONG *base, char *errmsg)
{
	*base = g_image_base;
	return 0;
}

EASY_CTYPES_SPEC
int get_exception_record64(EXCEPTION_RECORD64 *result, char *errmsg)
{
	*result = g_last_exception64;
	return 0;
}

EASY_CTYPES_SPEC
int get_last_breakpoint_address(uint64_t *addr, char *errmsg)
{
	*addr = g_last_breakpoint;
	return 0;
}

/*****************************************************************************/
/* INITIALIZATION, ENTRYPOINT */
/*****************************************************************************/

int client_setup(char *errmsg)
{
	int rc = ERROR_UNSPECIFIED;
	HRESULT hResult;

	report(NULL, "setup()\n");

	hResult = DebugCreate(__uuidof(IDebugClient5), (void **)&g_Client);
	if(hResult != S_OK)
	{
		report(errmsg, "ERROR: getting IDebugClient5\n");
		goto cleanup;
	}

	if ((hResult = g_Client->QueryInterface(__uuidof(IDebugControl), (void**)&g_Control)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&g_Data)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugRegisters), (void**)&g_Registers)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugSymbols), (void**)&g_Symbols)) != S_OK ||
		(hResult = g_Client->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&g_Objects)) != S_OK)
	{
		report(errmsg, "ERROR: getting client debugging interface\n");
		goto cleanup;
	}

	if ((hResult = g_Client->SetEventCallbacks(&g_EventCb)) != S_OK)
	{
		report(errmsg, "ERROR: SetEventCallbacks() returned 0x%08X\n", hResult);
		goto cleanup;
	}

	rc = 0;
	cleanup:
	return rc;
}

int client_teardown(void)
{
	report(NULL, "teardown()\n");

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
			report(NULL, "DLL_PROCESS_DETACH\n");
			client_teardown();
			break;

		case DLL_PROCESS_ATTACH:
			report(NULL, "DLL_PROCESS_ATTACH\n");
			/* do NOT initialize here */
			/* SEE: https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain */
			break;

		case DLL_THREAD_ATTACH:
			report(NULL, "DLL_THREAD_ATTACH\n");
			break;

		case DLL_THREAD_DETACH:
			report(NULL, "DLL_THREAD_DETACH\n");
			break;

		default:
			report(NULL, "unknown fdwReason: %d\n", fdwReason);
			break;
	}

	return true;
}

