#include "Win32Tools.h"

static void _clean_things (HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char *pErrorMessage);

DWORD
get_pid_by_name (char *proc_name)
{
	DWORD dwPID = 0;

	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (!Process32First(hSnapshot, &pe32))
		return 0;

	while (Process32Next(hSnapshot, &pe32))
	{
		if (!strcmp(proc_name, pe32.szExeFile))
		{
			dwPID = pe32.th32ProcessID;
			break;
		}

		Sleep(1);
	}

	CloseHandle(hSnapshot);

	return dwPID;
}

int
read_from_memory (HANDLE process, unsigned char *buffer, DWORD addr, unsigned int size)
{
	unsigned int bytes_left = size;
	unsigned int bytes_to_read;
	unsigned int total_read = 0;
	static unsigned char tempbuf[128*1024];
	DWORD bytes_read;
	int res = 0;

	while (bytes_left)
	{
		bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;

		if (!ReadProcessMemory(process, (LPCVOID) addr + total_read, tempbuf, bytes_to_read, &bytes_read))
		{
			res = GetLastError();
			if (res != ERROR_PARTIAL_COPY)
				warning("GetLastError() = %d (http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx)", res);
		}

		if (bytes_read != bytes_to_read)
			break;

		memcpy (buffer + total_read, tempbuf, bytes_read);

		bytes_left -= bytes_read;
		total_read += bytes_read;
	}

	return res;
}

int
write_to_memory (HANDLE process, unsigned char *buffer, DWORD addr, unsigned int size)
{
	DWORD bytes_read;

	if (!WriteProcessMemory(process, (PVOID) addr, buffer, size, &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x -> 0x%.8x)", addr, addr + size);
		return 0;
	}

	return bytes_read;
}

HANDLE
get_handle_by_name (char *proc_name)
{
	int pid = get_pid_by_name(proc_name);

	return get_handle_from_pid(pid);
}

int
inject_dll_in_process (DWORD pid, char *dll_path)
{
	int path_len = strlen(dll_path) + 1;
	HANDLE process;
	LPVOID data;
	HANDLE handle;
	DWORD thread_id;

	if ((process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)) == NULL)
	{
		warning("OpenProcess failed (%s)", dll_path);
		return 0;
	}

	if((data = VirtualAllocEx(process, NULL, path_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL)
	{
		warning("VirtualAlloc failed");
		return 0;
	}

	if ((WriteProcessMemory(process, data, dll_path, path_len, 0)) == 0)
	{
		warning("WriteProcessMemory failed");
		return 0;
	}

	if ((handle = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE) GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA"), data, 0, &thread_id)) == NULL)
	{
		warning("CreateRemoteThread failed.");
		return 0;
	}

	WaitForSingleObject(handle, INFINITE);
	VirtualFreeEx(process, data, 0, MEM_DECOMMIT);
	CloseHandle(process);
	CloseHandle(handle);

	return 1;
}

HANDLE
get_handle_from_pid (DWORD pid)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;

	while (hHandle == INVALID_HANDLE_VALUE)
	{
		hHandle = OpenProcess (
			PROCESS_ALL_ACCESS,
			FALSE, pid
		);

		Sleep(1);
	}

	return hHandle;
}

void
exit_process (HANDLE handle)
{
	DWORD code;

	GetExitCodeProcess(handle, &code);
	TerminateProcess(handle, code);
}

void
kill_process_by_name (char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof (pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);

	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD) pEntry.th32ProcessID);

			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}

		hRes = Process32Next(hSnapShot, &pEntry);
	}

	CloseHandle(hSnapShot);
}

inline unsigned int align_to_boundary(unsigned int address, unsigned int boundary) {
	return (((address + boundary - 1) / boundary) * boundary);
}

PIMAGE_SECTION_HEADER add_section(const char *section_name, unsigned int section_size, void *image_addr)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)image_addr;

	if (dos_header->e_magic != 0x5A4D)
	{
		wprintf(L"Could not retrieve DOS header from %p", image_addr);
		return NULL;
	}

	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)dos_header + dos_header->e_lfanew);

	if (nt_headers->OptionalHeader.Magic != 0x010B)
	{
		wprintf(L"Could not retrieve NT header from %p", dos_header);
		return NULL;
	}

	const int name_max_length = 8;

	PIMAGE_SECTION_HEADER last_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections - 1);
	PIMAGE_SECTION_HEADER new_section = IMAGE_FIRST_SECTION(nt_headers) + (nt_headers->FileHeader.NumberOfSections);
	memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));
	new_section->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	memcpy(new_section->Name, section_name, name_max_length);
	new_section->Misc.VirtualSize = section_size;
	new_section->PointerToRawData = align_to_boundary(last_section->PointerToRawData + last_section->SizeOfRawData,
	nt_headers->OptionalHeader.FileAlignment);
	new_section->SizeOfRawData = align_to_boundary(section_size, nt_headers->OptionalHeader.SectionAlignment);
	new_section->VirtualAddress = align_to_boundary(last_section->VirtualAddress + last_section->Misc.VirtualSize,
	nt_headers->OptionalHeader.SectionAlignment);
	nt_headers->OptionalHeader.SizeOfImage =  new_section->VirtualAddress + new_section->Misc.VirtualSize;
	nt_headers->FileHeader.NumberOfSections++;

	return new_section;
}
void
error_exit (LPTSTR lpszFunction)
{
	LPTSTR  error;

	error = 0;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
				  NULL, GetLastError(), 0, (LPTSTR)&error, 0, NULL);

	MessageBoxA(NULL, error, lpszFunction, MB_OK | MB_ICONWARNING);

	exit(EXIT_FAILURE);
}

BOOL enable_debug_privileges ()
{
	HANDLE hToken = 0;
	TOKEN_PRIVILEGES newPrivs;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		warning("Debug privilege : OpenProcessToken ERROR.");
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &newPrivs.Privileges[0].Luid))
	{
		warning("Debug privilege : LookupPrivilegeValue ERROR.");
		CloseHandle(hToken);
		return FALSE;
	}

	newPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	newPrivs.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(hToken, FALSE, &newPrivs, cb, NULL, NULL))
	{
		warning("Debug privilege : AdjustTokenPrivileges ERROR.");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

HWND
get_hwnd_from_title (char *title)
{
	return FindWindowA (NULL, title);
}

HWND get_hwnd_from_pid (DWORD pid)
{
	HWND hwnd = NULL;

	do {
		hwnd = FindWindowEx (NULL, hwnd, NULL, NULL);
		DWORD window_pid = 0;
		GetWindowThreadProcessId (hwnd, &window_pid);

		if (window_pid == pid)
			return hwnd;

	} while (hwnd != NULL);

	return NULL;
}

MODULEENTRY32 *
get_module_entry (char *process_name, DWORD pid, HWND window)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(8u, pid);
	MODULEENTRY32 *me = (MODULEENTRY32 *) malloc(sizeof(MODULEENTRY32));

	me->dwSize = 0;
	me->modBaseSize = 0;
	me->modBaseAddr = 0;
	me->hModule = NULL;

	if (snapshot == INVALID_HANDLE_VALUE)
	{
		warning("CreateToolhelp32Snapshot failed : GetLastError() = %d", (int) GetLastError());
		return NULL;
	}

	else
	{
		me->dwSize = sizeof(MODULEENTRY32);

		if (Module32First(snapshot, me))
		{
			while (strcmp(process_name, me->szModule))
			{
				if (!Module32Next(snapshot, me))
				{
					warning("%s module not found !", process_name);
					CloseHandle(snapshot);
					return NULL;
				}
			}

			CloseHandle(snapshot);

			return me;
		}

		else
		{
			CloseHandle(snapshot);
			warning("Module32First failed: GetLastError() = %d\n", (int) GetLastError());
			return NULL;
		}
	}
}

int
set_privilege (HANDLE hToken, LPCTSTR lpszPrivilege, int bEnablePrivilege)
{
	LUID luid;
	int bRet = FALSE;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			bRet = (GetLastError() == ERROR_SUCCESS);
		}
	}

	return bRet;
}

int
compare_pattern (const unsigned char *buffer, const unsigned char *pattern, const char *mask)
{
	for (;*mask;++mask, ++buffer, ++pattern)
	{
		if (*mask == 'x' && *buffer != *pattern)
			return 0;
	}

	return (*mask) == 0;
}

int
find_pattern (const unsigned char *buffer, DWORD size, unsigned char *pattern, char *mask)
{
	int i;

	for (i = 0; i < size; i ++)
	{
		if (compare_pattern((buffer + i), pattern, mask))
		{
			return i;
		}
	}

	return -1;
}

int
read_memory_as_int (HANDLE process, DWORD address)
{
	unsigned char buffer[4] = {0, 0, 0, 0};
	DWORD bytes_read;

	if (!ReadProcessMemory(process, (PVOID) address, buffer, 4, &bytes_read))
	{
		warning("ReadProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return bytes_to_int32 (buffer);
}

int
write_memory_as_int (HANDLE process, DWORD address, unsigned int value)
{
	unsigned char buffer[sizeof(int)];
	DWORD bytes_read;

	int32_to_bytes(value, buffer);

	if (!WriteProcessMemory(process, (PVOID) address, buffer, 4, &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return 1;
}

float
read_memory_as_float (HANDLE process, DWORD address)
{
	unsigned char buffer[sizeof(float)];
	DWORD bytes_read;

	if (!ReadProcessMemory(process, (PVOID) address, buffer, sizeof(float), &bytes_read))
	{
		warning("ReadProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return bytes_to_float (buffer);
}

int
write_memory_as_float (HANDLE process, DWORD address, float value)
{
	unsigned char buffer[sizeof(float)];
	DWORD bytes_read;

	float_to_bytes(value, buffer);

	if (!WriteProcessMemory(process, (PVOID) address, buffer, sizeof(float), &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return 1;
}

char modify_code_memory (DWORD *address, DWORD new_value)
{
	char res;
	DWORD old_protect;

	res = VirtualProtect(address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &old_protect);

	if (res != 0)
	{
		*address = new_value;
		VirtualProtect(address, sizeof(DWORD), old_protect, NULL);
	}

	return res;
}


int
get_path_from_process (HANDLE process, char *buffer)
{
	/*
	DWORD WINAPI GetModuleFileNameEx(
  __in	  HANDLE hProcess,
  __in_opt  HMODULE hModule,
  __out	 LPTSTR lpFilename,
  __in	  DWORD nSize
);
*/
	// Add psapi to the linker (libpsapi.a mandatory)
	HMODULE module = GetModuleHandleA("psapi.dll");
	DWORD WINAPI (*_GetModuleFileNameEx) (HANDLE a1, HMODULE a2, LPTSTR a3, DWORD a4);
	_GetModuleFileNameEx = (DWORD WINAPI (*)(HANDLE, HMODULE, LPTSTR, DWORD)) GetProcAddress (module, "GetModuleFileNameEx");

	if (_GetModuleFileNameEx == NULL)
	{
		warning("%d is NULL", _GetModuleFileNameEx);
	}

	if (_GetModuleFileNameEx(process, NULL, buffer, MAX_PATH) == 0)
	{
		warning("GetModuleFileNameEx failed.");
		return 0;
	}

	return 1;
}

EXPORT_FUNCTION int
bytes_to_int32 (unsigned char *bytes)
{
	return (((bytes[0] | (bytes[1] << 8)) | (bytes[2] << 0x10)) | (bytes[3] << 0x18));
}

int
is_win_nt (void)
{
	OSVERSIONINFO osv;
	osv.dwOSVersionInfoSize = sizeof(osv);
	GetVersionEx(&osv);

	return (osv.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

EXPORT_FUNCTION float
bytes_to_float (unsigned char *bytes)
{
	float res;
	memcpy(&res, bytes, sizeof(float));

	return res;
}

void
int32_to_bytes (unsigned int value, unsigned char *out)
{
	memcpy(out, &value, sizeof(int));
}

void
float_to_bytes (float value, unsigned char *out)
{
	memcpy(out, &value, sizeof(float));
}

void
console_set_pos (int x, int y)
{
	COORD coord;
	coord.X = x;
	coord.Y = y;

	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

void
console_stack_pos (int todo)
{
	static BbQueue xq = bb_queue_local_decl();
	static BbQueue yq = bb_queue_local_decl();

	CONSOLE_SCREEN_BUFFER_INFO SBInfo;
	int x, y;

	switch (todo)
	{
		case PUSH_POS:
			GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &SBInfo);
			bb_queue_add_raw(&xq, (int) SBInfo.dwCursorPosition.X);
			bb_queue_add_raw(&yq, (int) SBInfo.dwCursorPosition.Y);
		break;

		case POP_POS:
			x = (int) bb_queue_get_first(&xq);
			y = (int) bb_queue_get_first(&yq);
			console_set_pos(x, y);
		break;
	}
}

int
window_is_active (HWND window)
{
	return (window == GetForegroundWindow());
}

void
console_set_size (int w, int h)
{
	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r);
	MoveWindow(console, r.left, r.top, w, h, TRUE);
}

void
console_set_col (int col)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), col);
}

void
console_set_cursor_visibility (int visible)
{
	CONSOLE_CURSOR_INFO cursor;
	cursor.dwSize = 1;
	cursor.bVisible = visible;
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor);
}

void
_error (char *msg, ...)
{
	va_list args;
	console_set_col(0x0C);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_warning (char *msg, ...)
{
	va_list args;
	console_set_col(0x0E);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_info (char *msg, ...)
{
	va_list args;
	console_set_col(0x02);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_debug (char *msg, ...)
{
	#if DEBUG_ACTIVATED == 1
	va_list args;
	console_set_col(0x03);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
	#endif
}

LPVOID
file_to_mem (char *filename)
{
	HANDLE handle;
	DWORD bytes_read;
	DWORD file_size;
	LPVOID buffer = NULL;

	handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (handle)
	{
		file_size = GetFileSize(handle, NULL);

		if (file_size > 0)
		{
			buffer = VirtualAlloc(NULL, file_size, MEM_COMMIT, PAGE_READWRITE);

			if (buffer)
			{
				SetFilePointer(handle, 0, NULL, FILE_BEGIN);
				ReadFile(handle, buffer, file_size, &bytes_read, NULL);
			}
		}

		CloseHandle(handle);
	}

	return buffer;
}

void
exec_file (char *file_path, LPVOID mem_file)
{
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS nt_headers;
	PIMAGE_SECTION_HEADER section_header;
	PROCESS_INFORMATION process_info;
	STARTUPINFOA startup_info;
	PCONTEXT context;
	PDWORD image_base;
	NtUnmapViewOfSection xNtUnmapViewOfSection;
	LPVOID ptr_image_base;
	int loop;

	dos_header = (PIMAGE_DOS_HEADER) mem_file;

	if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
	{
		nt_headers = (PIMAGE_NT_HEADERS)((DWORD)(mem_file) + dos_header->e_lfanew);

		if (nt_headers->Signature == IMAGE_NT_SIGNATURE)
		{
			RtlZeroMemory(&startup_info, sizeof(startup_info));
			RtlZeroMemory(&process_info, sizeof(process_info));

			if (CreateProcessA(file_path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info))
			{
				context = (PCONTEXT)(VirtualAlloc(NULL, sizeof(context), MEM_COMMIT, PAGE_READWRITE));
				context->ContextFlags = CONTEXT_FULL;

				if (GetThreadContext(process_info.hThread, (LPCONTEXT)(context)))
				{
					ReadProcessMemory(process_info.hProcess, (LPCVOID)(context->Ebx + 8), (LPVOID)(&image_base), 4, NULL);

					if ((DWORD)(image_base) == nt_headers->OptionalHeader.ImageBase)
					{
						xNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
						xNtUnmapViewOfSection(process_info.hProcess, (PVOID)(image_base));
					}

					ptr_image_base = VirtualAllocEx(process_info.hProcess, (LPVOID)(nt_headers->OptionalHeader.ImageBase), nt_headers->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

					if (ptr_image_base)
					{
						WriteProcessMemory(process_info.hProcess, ptr_image_base, mem_file, nt_headers->OptionalHeader.SizeOfHeaders, NULL);

						for (loop = 0; loop < nt_headers->FileHeader.NumberOfSections; loop++)
						{
							section_header = (PIMAGE_SECTION_HEADER)((DWORD)(mem_file) + dos_header->e_lfanew + 248 + (loop * 40));
							WriteProcessMemory(process_info.hProcess, (LPVOID)((DWORD)(ptr_image_base) + section_header->VirtualAddress), (LPVOID)((DWORD)(mem_file) + section_header->PointerToRawData), section_header->SizeOfRawData, NULL);
						}

						WriteProcessMemory(process_info.hProcess, (LPVOID)(context->Ebx + 8), (LPVOID)(&nt_headers->OptionalHeader.ImageBase), 4, NULL);
						context->Eax = (DWORD)(ptr_image_base) + nt_headers->OptionalHeader.AddressOfEntryPoint;
						SetThreadContext(process_info.hThread, (LPCONTEXT)(context));
						ResumeThread(process_info.hThread);
					}
				}
			}
		}
	}

	VirtualFree(mem_file, 0, MEM_RELEASE);
}

DWORD
find_pattern_process (HANDLE process, DWORD start, DWORD end, unsigned char *pattern, char* mask)
/*
*	Exemple :
*	char *pattern = "\x00\xC0\xB7\x44\x00\xC0";
*	DWORD address = find_pattern_process(process, 0x800000, 0xF00000, (PBYTE) pattern, "xxx??x");
*	returns 0 on error
*/
{
	DWORD size = end - start;
	unsigned char *buffer = (unsigned char *) malloc(size + 1);

	if (!buffer)
	{
		warning("buffer malloc (size %d) failed.", size + 1);
	}

	else if (ReadProcessMemory(process, (PVOID) start, buffer, size, NULL) == FALSE)
	{
		warning("(0x%.8x - 0x%.8x) RPM failed.", start, end);
		free(buffer);
	}

	else
	{
		DWORD address = find_pattern(buffer, size, pattern, mask);
		free(buffer);

		if (address)
			return start + address;
	}

	return 0;
}

int
hex_to_dec (char* hex)
{
	int ret = 0, t = 0, n = 0;
	const char *c = hex;

	while (*c && (n < 16))
	{
		if ((*c >= '0') && (*c <= '9'))
			t = (*c - '0');

		else if ((*c >= 'A') && (*c <= 'F'))
			t = (*c - 'A' + 10);

		else if((*c >= 'a') && (*c <= 'f'))
			t = (*c - 'a' + 10);

		else
			break;

		n++;
		ret *= 16;
		ret += t;
		c++;

		if (n >= 8)
			break;
	}

	return ret;
}

void
debug_mask_pattern (char *mask, unsigned char *pattern)
{
	int i;
	int len = strlen(mask);

	for (i = 0; i < len; i++)
	{
		console_set_col((mask[i] == 'x') ? 0x02 : 0x0C);
		printf("%.2x ", pattern[i]);

		if (i % 16 == 15)
			printf("\n");
	}

	console_set_col(0x07);
}

char *
create_mask_from_file (char *filename)
{
	char *data = file_get_contents(filename);
	int pos = 0;
	int flag = 1;
	int data_len = strlen(data);
	int i;

	BbQueue *line1 = NULL;
	BbQueue *line2 = NULL;
	char *mask = NULL;
	char str[1024 * 100];
	memset(str, '\0', sizeof(str));

	while (pos <= data_len)
	{
		if (flag)
		{
			pos = str_getline(data, str, sizeof(str), pos);

			line1 = str_explode(str, " ");
			mask  = str_malloc_clear(bb_queue_get_length(line1) + 1);

			for (i = 0; i < bb_queue_get_length(line1); i++)
				mask[i] = 'x';

			pos = str_getline(data, str, sizeof(str), pos);

			if (pos < data_len)
				line2 = str_explode(str, " ");

			else
				return mask;

			flag = 0;
		}

		else
		{
			pos   = str_getline(data, str, sizeof(str), pos);
			line2 = str_explode(str, " ");
		}

		if (bb_queue_get_length(line1) != bb_queue_get_length(line2))
		{
			warning("Pattern lines aren't the same length.");
			return NULL;
		}

		for (i = 1; i < bb_queue_get_length(line1) + 1; i++)
		{
			int hex1 = (int) hex_to_dec((char *) bb_queue_pick_nth(line1, i));
			int hex2 = (int) hex_to_dec((char *) bb_queue_pick_nth(line2, i));

			if ((mask[i-1] == 'x') && (hex1 != hex2))
				mask[i-1] = '?';
		}

		if (pos == -1 || pos >= data_len)
		{
			// End job
			bb_queue_free_all(line1, free);
			bb_queue_free_all(line2, free);
			free(data);

			return mask;
		}

		bb_queue_free_all(line1, free);
		line1 = line2;
	}

	return mask;
}

DWORD
get_baseaddr (char *module_name)
{
	MODULEENTRY32 module_entry = {};
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, get_pid_by_name(module_name));

	if (!snapshot)
		return 0;

	module_entry.dwSize = sizeof(module_entry);
	BOOL bModule = Module32First(snapshot, &module_entry);

	while (bModule)
	{
		if (!strcmp(module_entry.szModule, module_name))
		{
			CloseHandle(snapshot);
			return (DWORD) module_entry.modBaseAddr;
		}

		bModule = Module32Next(snapshot, &module_entry);
	}

	CloseHandle(snapshot);

	return 0;
}

static void
_clean_things (HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char *pErrorMessage)
{
	if (pErrorMessage != NULL)
		printf ("%s\n", pErrorMessage);

	if (hFile != NULL)
		CloseHandle (hFile);

	if (pFile != NULL)
		UnmapViewOfFile (pFile);

	if (hMapping != NULL)
		CloseHandle (hMapping);
}

PIMAGE_SECTION_HEADER
GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	unsigned i;

	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + section->Misc.VirtualSize)))
			return section;
	}

	return 0;
}


LPVOID
get_ptr_from_rva (DWORD rva, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase)
{
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;

	pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);

	if (!pSectionHdr)
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress-pSectionHdr->PointerToRawData);
	return (PVOID) (imageBase + rva - delta);
}


void
dump_iat (char *filename)
{
	PIMAGE_DOS_HEADER dos_header;
	LPVOID file_mapping = map_file(filename);
	PIMAGE_NT_HEADERS pNTHeader;
	dos_header = (PIMAGE_DOS_HEADER) file_mapping;
	DWORD base = (DWORD)dos_header;

	pNTHeader = make_ptr (PIMAGE_NT_HEADERS, dos_header, dos_header->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR importDesc;
	PIMAGE_SECTION_HEADER pSection;
	PIMAGE_THUNK_DATA thunk, thunkIAT=0;
	PIMAGE_IMPORT_BY_NAME pOrdinalName;
	DWORD importsStartRVA;
	PSTR pszTimeDate;

	importsStartRVA = GetImgDirEntryRVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (!importsStartRVA)
		return;

	pSection = GetEnclosingSectionHeader(importsStartRVA, pNTHeader);

	if (!pSection)
		return;

	importDesc = (PIMAGE_IMPORT_DESCRIPTOR) get_ptr_from_rva(importsStartRVA,pNTHeader,base);

	if (!importDesc)
		return;

	printf("Imports Table:\n");

	while (1)
	{
		if ((importDesc->TimeDateStamp == 0)
		&&  (importDesc->Name == 0))
			break;

		printf("  %s\n", (char*) get_ptr_from_rva(importDesc->Name, pNTHeader, base) );
		printf("  OrigFirstThunk:  %08X (Unbound IAT)\n", (int) importDesc->Characteristics);

		pszTimeDate = ctime((PLONG)&importDesc->TimeDateStamp);
		printf("  TimeDateStamp:   %08X", (int) importDesc->TimeDateStamp );
		printf( pszTimeDate ?  " -> %s" : "\n", pszTimeDate );

		printf("  ForwarderChain:  %08X\n", (int) importDesc->ForwarderChain);
		printf("  First thunk RVA: %08X\n", (int) importDesc->FirstThunk);

		thunk = (PIMAGE_THUNK_DATA)importDesc->Characteristics;
		thunkIAT = (PIMAGE_THUNK_DATA)importDesc->FirstThunk;

		if (thunk == 0)
		{
			thunk = thunkIAT;

			if (thunk == 0)
				return;
		}

		// Adjust the pointer to point where the tables are in the
		// mem mapped file.
		thunk = (PIMAGE_THUNK_DATA) get_ptr_from_rva((DWORD)thunk, pNTHeader, base);

		if (!thunk )
			return;

		thunkIAT = (PIMAGE_THUNK_DATA) get_ptr_from_rva((DWORD)thunkIAT, pNTHeader, base);

		printf("  Ordn  Name\n");

		while (1)
		{
			if (thunk->u1.AddressOfData == 0)
				break;

			if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				printf("  %4u", (int) IMAGE_ORDINAL(thunk->u1.Ordinal));
			}

			else
			{
				pOrdinalName = (PIMAGE_IMPORT_BY_NAME) thunk->u1.AddressOfData;
				pOrdinalName = (PIMAGE_IMPORT_BY_NAME) get_ptr_from_rva((DWORD)pOrdinalName, pNTHeader, base);

				printf("  %4u  %s", (int) pOrdinalName->Hint, pOrdinalName->Name);
			}

			// If the user explicitly asked to see the IAT entries, or
			// if it looks like the image has been bound, append the address
			if (importDesc->TimeDateStamp)
				printf(" (Bound to: %08X)", (int) thunkIAT->u1.Function);

			printf("\n");

			thunk++;			// Advance to next thunk
			thunkIAT++;		 // advance to next thunk
		}

		importDesc++;   // advance to next IMAGE_IMPORT_DESCRIPTOR
		printf("\n");
	}
}

int
dump_eat (char *file_path)
{
	/* The IMAGE_EXPORT_DIRECTORY :
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD	MajorVersion;
	WORD	MinorVersion;
	DWORD   Name;					// DLL name
	DWORD   Base;					// ordinal base
	DWORD   NumberOfFunctions;		// address table entries
	DWORD   NumberOfNames;			// number of name pointers
	DWORD   AddressOfFunctions;	 // Export address table RVA
	DWORD   AddressOfNames;		 // Name pointer RVA
	DWORD   AddressOfNameOrdinals;  // Ordinal table RVA */

	char buffer1[500] = {0};
	char buffer2[500] = {0};

	HANDLE hFile = 0, hMapping = 0;
	DWORD FileSize = 0, ExportTableRVA = 0, ImageBase = 0;
	PBYTE pFile = 0;
	PWORD pOrdinals = 0;
	PDWORD pFuncs = 0;
	PIMAGE_DOS_HEADER ImageDosHeader = 0;
	PIMAGE_NT_HEADERS ImageNtHeaders = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;

	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_clean_things (NULL, NULL, NULL, "Can't open the required DLL");
		return FALSE;
	}

	FileSize = GetFileSize (hFile, NULL);
	if (FileSize == 0)
	{
		_clean_things (hFile, NULL, NULL, "FileSize is 0 !");
		return FALSE;
	}

	hMapping = CreateFileMapping (hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		_clean_things (hFile, NULL, NULL, "Can't create the file mapping !");
		return FALSE;
	}

	pFile = (PBYTE) MapViewOfFile (hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFile == NULL)
	{
		_clean_things (hFile, hMapping, NULL, "Can't map the requested file !");
		return FALSE;
	}

	ImageBase = (DWORD)pFile;
	ImageDosHeader = (PIMAGE_DOS_HEADER) pFile;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
		return FALSE;
	}

	ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (DWORD) ImageDosHeader);

	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
		return FALSE;
	}

	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableRVA == 0)
	{
		_clean_things (hFile, hMapping, pFile, "Export table not found !");
		return FALSE;
	}

	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) (ExportTableRVA + ImageBase);


	snprintf(buffer1, sizeof(buffer1), "TimeDateStamp: 0x%08lX - ", ImageExportDirectory->TimeDateStamp);
	strncat(buffer1, ctime((time_t*)&ImageExportDirectory->TimeDateStamp), sizeof(buffer1));

	snprintf(buffer2, sizeof (buffer2),
		"\r\nMajor Version: %i\r\n"
		"Minor Version: %i\r\n"
		"Name RVA: 0x%08lX - DLL Name : %s\r\n"
		"Ordinal Base: 0x%08lX\r\n"
		"Address Table Entries: %d\r\n"
		"Number of Name Pointers: %d\r\n"
		"Export Table Address RVA: 0x%08lX\r\n"
		"Name Pointer RVA: 0x%08lX\r\n"
		"Ordinal Table RVA: 0x%08lX",
		ImageExportDirectory->MajorVersion,
		ImageExportDirectory->MinorVersion,
		ImageExportDirectory->Name,
		(char *)ImageExportDirectory->Name + ImageBase,
		ImageExportDirectory->Base,
		(int) ImageExportDirectory->NumberOfFunctions,
		(int) ImageExportDirectory->NumberOfNames,
		ImageExportDirectory->AddressOfFunctions,
		ImageExportDirectory->AddressOfNames,
		ImageExportDirectory->AddressOfNameOrdinals);

	strncat (buffer1, buffer2, sizeof (buffer1));
	printf("%s\n", buffer1);

	pOrdinals = (PWORD) (ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
	pFuncs = (PDWORD) (ImageExportDirectory->AddressOfFunctions + ImageBase);
	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;

	DWORD ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD ETUpperBoundarie = ExportTableRVA + ExportTableSize;

	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
	{
		snprintf ((LPTSTR) buffer1, sizeof (buffer1), "Ord: %04lX (0x%08lX)", ImageExportDirectory->Base + i, pFuncs[i]);

		if (pOrdinals[i] < NumOfNames)
		{
			PDWORD pNamePointerRVA =(PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
			PCHAR pFuncName = (PCHAR) (pNamePointerRVA[i] + (DWORD) ImageBase);
			snprintf ((LPTSTR)buffer2, sizeof (buffer2), " - %s", pFuncName);
			strncat (buffer1, buffer2, sizeof (buffer1));

			if ( (pFuncs[i] >= ExportTableRVA) && (pFuncs[i] <= ETUpperBoundarie) )
			{
				PDWORD pFwdFunc = (PDWORD) (pFuncs[i] + (DWORD)ImageBase);
				snprintf (buffer2, sizeof (buffer2), " - Fwd to: %s", (char *)pFwdFunc);
				strncat (buffer1, buffer2, sizeof (buffer1));
			}
		}

		printf("%s\n", buffer1);
	}

	_clean_things (hFile, hMapping, pFile, NULL);

	return TRUE;
}

int
is_pe (LPVOID mapping)
{
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER) mapping;

	if (dos_header->e_magic == IMAGE_DOS_SIGNATURE)
	{
		PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS) ((char*) dos_header + dos_header->e_lfanew);
		return (nt_headers->Signature == IMAGE_NT_SIGNATURE);
	}

	return 0;
}

typedef HGLOBAL ( WINAPI * tLoadRec )( HMODULE hModule, HRSRC hResInfo );
tLoadRec oLoadRec;

HGLOBAL __stdcall get_loadrec (HMODULE hModule, HRSRC hResInfo)
{
	__asm__("PUSHAD");

	{
		char szFileName[256] = { 0 };
		GetModuleFileName(hModule, szFileName, sizeof(szFileName));

		if (strstr (szFileName, "EHSvc"))
		{
			hModule = NULL;
		}
	}

	__asm__("POPAD");

	return (*oLoadRec) (hModule, hResInfo);
}

void *detour_loadrec (BYTE *src, const BYTE *dst, const int len)
{
	BYTE *jmp = (BYTE*) malloc(len + 5);
	DWORD dwBack;

	VirtualProtect(src, len, PAGE_EXECUTE_READWRITE, &dwBack);

	memcpy(jmp, src, len);
	jmp += len;

	jmp[0] = 0xE9;
	*(DWORD*)(jmp+1) = (DWORD)(src+len - jmp) - 5;

	src[0] = 0xE9;
	*(DWORD*)(src+1) = (DWORD)(dst - src) - 5;

	for (int i = 5; i < len; i++)
		src[i]=0x90;

	VirtualProtect(src, len, dwBack, &dwBack);

	return (jmp-len);
}

void
add_to_startup (char *key_name)
{
	char path[MAX_PATH];
	HKEY key;

	GetModuleFileName(NULL, path, MAX_PATH);

	RegOpenKey(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", &key);

	RegSetValueEx(key, key_name, 0, REG_SZ, (LPBYTE)path, sizeof(path));
	RegCloseKey(key);
}

void
get_mouse_pos (int *x, int *y)
{
	POINT pos;

	GetCursorPos(&pos);
	*x = pos.x;
	*y = pos.y;
}

void
hook_iat (char *function_name, LPDWORD hook_callback)
{
	DWORD new_protect, old_protect;

	FILE *winlog = fopen("logwin32.txt", "w+");

	LPDWORD callback = get_address_in_iat(function_name);

	fprintf(winlog, "%s function address : 0x%x\n", function_name, (int) callback);
	fclose(winlog);

	if (callback <= 0)
	{
		printf("%s : Error during retrieve of the function name \"%s\" in IAT", __FUNCTION__, function_name);
		return;
	}

	VirtualProtect(callback, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE, &new_protect);
	*callback = (DWORD) hook_callback;

	VirtualProtect(callback, sizeof(LPDWORD), new_protect, &old_protect);
}

LPDWORD
get_address_in_iat (char *function_name)
{
	HANDLE handle = NULL;
	PIMAGE_DOS_HEADER dos_header = NULL;
	PIMAGE_NT_HEADERS nt_headers = NULL;
	PIMAGE_IMPORT_DESCRIPTOR import_descriptor = NULL;
	PIMAGE_THUNK_DATA32 import_table_name = NULL;
	PIMAGE_THUNK_DATA32 import_table_address = NULL;
	PIMAGE_IMPORT_BY_NAME import_name = NULL;

	if((handle = GetModuleHandle(NULL)) == NULL)
		return (LPDWORD) -1;

	dos_header = (PIMAGE_DOS_HEADER) handle;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return (LPDWORD) -2;

	nt_headers		=  (PIMAGE_NT_HEADERS) (dos_header->e_lfanew + (DWORD) dos_header); // Nt Headers
	import_descriptor =  (PIMAGE_IMPORT_DESCRIPTOR)( (DWORD) ((PVOID)nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) + (DWORD) dos_header); // Import Descriptor

	while ((*(PDWORD)import_descriptor))
	{
		import_table_name	= (PIMAGE_THUNK_DATA32) (import_descriptor->OriginalFirstThunk + (DWORD) dos_header);
		import_table_address = (PIMAGE_THUNK_DATA32) (import_descriptor->FirstThunk + (DWORD) dos_header);

		while (*(PDWORD) import_table_name)
		{
			import_name = (PIMAGE_IMPORT_BY_NAME) (import_table_name->u1.AddressOfData + (DWORD) dos_header);

			if (!strcmp((PCHAR) import_name->Name, function_name))
				return &(import_table_address->u1.Function);

			import_table_name++;
			import_table_address++;
		}

		import_descriptor++;
	}

	return 0;
}

LPVOID
map_file (char *file_path)
{
	LPVOID ptr_map = NULL;
	HANDLE handle_file = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (handle_file != INVALID_HANDLE_VALUE)
	{
		HANDLE handle_map = CreateFileMapping(handle_file, NULL, PAGE_READONLY, 0, 0, 0);

		if (handle_map != NULL)
			ptr_map = MapViewOfFile(handle_map, FILE_MAP_READ, 0, 0, 0);
	}

	return ptr_map;
}


int
GetFilePointer (HANDLE FileHandle)
{
	return SetFilePointer(FileHandle, 0, 0, FILE_CURRENT);
}



#if COMPILE_GDI
int
save_bmp_file (char *filename, HBITMAP bitmap, HDC bitmapDC, int width, int height)
{
	HBITMAP OffscrBmp=NULL; // bitmap that is converted to a DIB
	HDC OffscrDC=NULL;	  // offscreen DC that we can select OffscrBmp into
	LPBITMAPINFO lpbi=NULL; // bitmap format info; used by GetDIBits
	LPVOID lpvBits=NULL;	// pointer to bitmap bits array
	HANDLE BmpFile=INVALID_HANDLE_VALUE;	// destination .bmp file
	BITMAPFILEHEADER bmfh;  // .bmp file header

	// We need an HBITMAP to convert it to a DIB:
	if ((OffscrBmp = CreateCompatibleBitmap(bitmapDC, width, height)) == NULL)
		return 0;

	// The bitmap is empty, so let's copy the contents of the surface to it.
	// For that we need to select it into a device context. We create one.
	if ((OffscrDC = CreateCompatibleDC(bitmapDC)) == NULL)
		return 0;

	// Select OffscrBmp into OffscrDC:
	HBITMAP OldBmp = (HBITMAP)SelectObject(OffscrDC, OffscrBmp);

	// Now we can copy the contents of the surface to the offscreen bitmap:
	BitBlt(OffscrDC, 0, 0, width, height, bitmapDC, 0, 0, SRCCOPY);

	// GetDIBits requires format info about the bitmap. We can have GetDIBits
	// fill a structure with that info if we pass a NULL pointer for lpvBits:
	// Reserve memory for bitmap info (BITMAPINFOHEADER + largest possible
	// palette):
	char *str = malloc(sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD));

	if ((lpbi = (LPBITMAPINFO)(str)) == NULL)
		return 0;


	ZeroMemory(&lpbi->bmiHeader, sizeof(BITMAPINFOHEADER));
	lpbi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	// Get info but first de-select OffscrBmp because GetDIBits requires it:
	SelectObject(OffscrDC, OldBmp);
	if (!GetDIBits(OffscrDC, OffscrBmp, 0, height, NULL, lpbi, DIB_RGB_COLORS))
		return 0;

	// Reserve memory for bitmap bits:
	str = malloc(lpbi->bmiHeader.biSizeImage);

	if ((lpvBits = str) == NULL)
		return 0;

	// Have GetDIBits convert OffscrBmp to a DIB (device-independent bitmap):
	if (!GetDIBits(OffscrDC, OffscrBmp, 0, height, lpvBits, lpbi, DIB_RGB_COLORS))
		return 0;

	// Create a file to save the DIB to:
	if ((BmpFile = CreateFile(filename,
							  GENERIC_WRITE,
							  0, NULL,
							  CREATE_ALWAYS,
							  FILE_ATTRIBUTE_NORMAL,
							  NULL)) == INVALID_HANDLE_VALUE)

							  return 0;

	DWORD Written;	// number of bytes written by WriteFile

	// Write a file header to the file:
	bmfh.bfType = 19778;		// 'BM'
	// bmfh.bfSize = ???		// we'll write that later
	bmfh.bfReserved1 = bmfh.bfReserved2 = 0;
	// bmfh.bfOffBits = ???	 // we'll write that later
	if (!WriteFile(BmpFile, &bmfh, sizeof(bmfh), &Written, NULL))
		return 0;

	if (Written < sizeof(bmfh))
		return 0;

	// Write BITMAPINFOHEADER to the file:
	if (!WriteFile(BmpFile, &lpbi->bmiHeader, sizeof(BITMAPINFOHEADER), &Written, NULL))
		return 0;

	if (Written < sizeof(BITMAPINFOHEADER))
			return 0;

	// Calculate size of palette:
	int PalEntries;
	// 16-bit or 32-bit bitmaps require bit masks:
	if (lpbi->bmiHeader.biCompression == BI_BITFIELDS)
		PalEntries = 3;
	else
		// bitmap is palettized?
		PalEntries = (lpbi->bmiHeader.biBitCount <= 8) ?
			// 2^biBitCount palette entries max.:
			(int)(1 << lpbi->bmiHeader.biBitCount)
		// bitmap is TrueColor -> no palette:
		: 0;
	// If biClrUsed use only biClrUsed palette entries:
	if(lpbi->bmiHeader.biClrUsed)
		PalEntries = lpbi->bmiHeader.biClrUsed;

	// Write palette to the file:
	if(PalEntries){
		if (!WriteFile(BmpFile, &lpbi->bmiColors, PalEntries * sizeof(RGBQUAD), &Written, NULL))
			return 0;

		if (Written < PalEntries * sizeof(RGBQUAD))
			return 0;
		}

	// The current position in the file (at the beginning of the bitmap bits)
	// will be saved to the BITMAPFILEHEADER:
	bmfh.bfOffBits = GetFilePointer(BmpFile);

	// Write bitmap bits to the file:
	if (!WriteFile(BmpFile, lpvBits, lpbi->bmiHeader.biSizeImage, &Written, NULL))
		return 0;

	if (Written < lpbi->bmiHeader.biSizeImage)
		return 0;

	// The current pos. in the file is the final file size and will be saved:
	bmfh.bfSize = GetFilePointer(BmpFile);

	// We have all the info for the file header. Save the updated version:
	SetFilePointer(BmpFile, 0, 0, FILE_BEGIN);
	if (!WriteFile(BmpFile, &bmfh, sizeof(bmfh), &Written, NULL))
		return 0;

	if (Written < sizeof(bmfh))
		return 0;

	return 1;
}


int
screen_capture (int x, int y, int width, int height, char *filename)
{
	// get a DC compat. w/ the screen
	HDC hDc = CreateCompatibleDC(0);

	// make a bmp in memory to store the capture in
	HBITMAP hBmp = CreateCompatibleBitmap(GetDC(0), width, height);

	// join em up
	SelectObject(hDc, hBmp);

	// copy from the screen to my bitmap
	BitBlt(hDc, 0, 0, width, height, GetDC(0), x, y, SRCCOPY);

	// save my bitmap
	int ret = save_bmp_file(filename, hBmp, hDc, width, height);

	// free the bitmap memory
	DeleteObject(hBmp);

	return ret;
}
#endif
