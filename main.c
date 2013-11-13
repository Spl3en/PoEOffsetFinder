/*
	Author : Spl3en

	Credits to
		SKU (www.ownedcore.com/forums/mmo/path-of-exile/poe-bots-programs/397918-source-basic-item-alerter.html)
	Thanks to
		vitek - testing
*/

#include "./Win32Tools/Win32Tools.h"
#include "./MemProc/MemProc.h"
#include <conio.h>

#define CLIENT_NAME "PathOfExile.exe"

int poe_cond (MEMORY_BASIC_INFORMATION *meminfo, void *arg) {
	return 1; // retrieve everything in .text
}

int get_recv_breakpoints (int *bp0, int *bp1, int *bp2, int *baseaddr, char *client_name, char *pydbg_filename)
/**
*	@Description : Retrieve the offsets of BP0, BP1 and BP2 in the PathOfExile process "Client.exe"
*	@param 	bp0				(out) Pointer on an allocated int
*	@param 	bp1				(out) Pointer on an allocated int
*	@param 	bp2				(out) Pointer on an allocated int
*	@param  baseaddr 		(out) Pointer on an allocated int
*	@param  pydbg_filename 	(in)  Filename of the pydbg script, or NULL
*/
{
	/*
		Position of ItemAlert Breakpoints :
				BaseAddress + 001D86B6  ║·  53            push ebx                                 ; ╓Arg4 :	_In_	int flags
				BaseAddress + 001D86B7  ║·  50            push eax                                 ; ║Arg3 :	_In_	int len
				BaseAddress + 001D86B8  ║·  8D8431 980002 lea eax, [esi+ecx+20098]                 ; ║
				BaseAddress + 001D86BF  ║·  8B0E          mov ecx, [dword ds:esi]                  ; ║
		BP1 ->	BaseAddress + 001D86C1  ║·  50            push eax                                 ; ║Arg2 :	_Out_	char *buf
				BaseAddress + 001D86C2  ║·  51            push ecx                                 ; ║Arg1 :	_In_	SOCKET s
				BaseAddress + 001D86C3  ║·  FF15 B0898801 call [dword ds:<&WS2_32.#16>]            ; └WS2_32.recv
		BP0 ->	BaseAddress + 001D86C9  ║·  8BF8          mov edi, eax
				[...]     				║
				BaseAddress + 001D870D  ║·  FFD2          call edx						<- Arg2 is unserialized here
		BP2 ->	BaseAddress + 001D870F  ║.  8B46 54       mov eax, [dword ds:esi+54]	<- We wait until the end of the deserialization to get Arg2
				[...]     				║
				BaseAddress + 001D8730  ║·  5B            pop ebx
				BaseAddress + 001D8731  └·  C3            retn
	*/

	unsigned char recv_call[] =
		"\x53"							// ║·  push ebx                     ; ╓Arg4
		"\x50"							// ║·  push eax                     ; ║Arg3
		"\x8D\x84\x31\x98\x00\x02\x00"	// ║·  lea eax, [esi+ecx+20098]     ; ║
		"\x8B\x0E"						// ║·  mov ecx, [dword ds:esi]      ; ║
		"\x50"							// ║·  push eax                     ; ║Arg2
		"\x51"							// ║·  push ecx                     ; ║Arg1
		"\xFF\x15\xB0\x89\x6C\x00";		// ║·  call [dword ds:WS2_32.recv]  ; └WS2_32.recv

	*bp0 = 0;
	*bp1 = 0;
	*bp2 = 0;
	*baseaddr = 0;

	MemProc *mp = memproc_new(client_name, "Path of Exile");
	memproc_refresh_handle(mp);

	if (!mp || !mp->proc) {
		error("Launch %s\n", client_name);
		return 0;
	}

	*baseaddr = get_baseaddr(client_name);

	//   TODO : get .text section offset properly
	int start_text = 0x1000 + *baseaddr;
	int end_text   = 0x1000 + 0x005E8000 + *baseaddr; // .text section size

	memproc_dump_details(mp, start_text, end_text, poe_cond, NULL);

	memproc_search(mp, recv_call, "xxxxxxxxxxxxxxx????", NULL, SEARCH_TYPE_BYTES);

	BbQueue *res = memproc_get_res(mp);

	if (bb_queue_get_length(res) <= 0) {
		error("Error: Pattern not found.\n");
		return 0;
	}

	if (bb_queue_get_length(res) > 1) {
		warning("More than one occurence found. Only the first is used, the rest is ignored.");
	}

	MemBlock *memblock = bb_queue_get_first(res);

	int bpf = memblock->addr + (sizeof(recv_call) - sizeof("\x50\x51\xFF\x15\xB0\x89\x6C\x00")); // position = push eax ; ║Arg2
	*bp1 = bpf - *baseaddr;
	*bp0 = bpf + 0x08 - *baseaddr;
	*bp2 = bpf + 0x4A - *baseaddr;

	if (pydbg_filename == NULL)
		// Don't write anything
		return 1;

	char *pythonfile = file_get_contents(pydbg_filename);

	if (pythonfile)
	{
		char *oldbp0 = str_bet(pythonfile, "BP0 = ", "\n");
		char *oldbp1 = str_bet(pythonfile, "BP1 = ", "\n");
		char *oldbp2 = str_bet(pythonfile, "BP2 = ", "\n");

		if (!oldbp0 || !oldbp1 || !oldbp2)
			printf("Malformed %s, cannot replace automatically the values. Please paste the values above manually.\n", pydbg_filename);

		else
		{
			char *newbp0 = str_dup_printf("0x%.8x + 0x00400000", *bp0);
			char *newbp1 = str_dup_printf("0x%.8x + 0x00400000", *bp1);
			char *newbp2 = str_dup_printf("0x%.8x + 0x00400000", *bp2);

			pythonfile = str_replace(oldbp0, newbp0, pythonfile);
			pythonfile = str_replace(oldbp1, newbp1, pythonfile);
			pythonfile = str_replace(oldbp2, newbp2, pythonfile);

			file_put_contents(pydbg_filename, pythonfile, NULL);

			info("%s saved.\n", pydbg_filename);
		}
	}

	return 1;
}

int main(int argc, char **argv)
{
	int bp0, bp1, bp2, baseaddr;
	char *client_name = CLIENT_NAME;

	if (argc > 1)
		client_name = argv[1];

	if (get_recv_breakpoints(&bp0, &bp1, &bp2, &baseaddr, client_name, "ItemAlertPoE.py"))
	{
		printf("BP0 = 0x%.8x + 0x00400000 #(0x%.8x)\n", bp0, bp0 + baseaddr);
		printf("BP1 = 0x%.8x + 0x00400000 #(0x%.8x)\n", bp1, bp1 + baseaddr);
		printf("BP2 = 0x%.8x + 0x00400000 #(0x%.8x)\n", bp2, bp2 + baseaddr);
	}

	console_set_col(0x07);
	printf("Smash something on your keyboard to quit...");
	getch();

    return 0;
}
