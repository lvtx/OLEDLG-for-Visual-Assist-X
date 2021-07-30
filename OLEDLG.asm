;#########################################################################
;		Assembler directives

.486
.model flat, stdcall
option casemap:none

;#########################################################################
;		Include file

include OLEDLG.inc
include PE.inc

.code

;#########################################################################
;		Common AddIn Procedures

DllEntry proc hinstDLL:HINSTANCE, fdwReason:DWORD, lpReserved:LPVOID
LOCAL LibPath[MAX_PATH]:BYTE
LOCAL lpAddress:DWORD
LOCAL dwSize:DWORD
LOCAL lpflOldProtect:DWORD
;LOCAL flOldProtect:DWORD

	pushad
	.if fdwReason == DLL_PROCESS_ATTACH
		mov eax, hinstDLL
		mov curr_hModule, eax

		invoke GetSystemDirectory, addr LibPath, MAX_PATH
		lea ebx, LibPath
		add eax, ebx

		mov edi, eax
		mov esi, offset strLoadLib
		mov ecx, 0Ch
		rep movsb

		mov ole_hModule, rv(LoadLibrary, addr LibPath)
		;DebugOut "LoadLibrary : [0x%.8X] [%hs]", ole_hModule, addr LibPath

		;mov vax_hModule, rv(LoadLibrary, offset strVaxNameA)
		mov vax_hModule, rv(GetModuleHandle, offset strVaxName)
		;DebugOut "GetModuleHandle : [0x%.8X] [%hs]", vax_hModule, offset strVaxName

		.if vax_hModule == 0
			invoke HideModule
		.else
			mov edi, eax
			; 检测PE文件是否有效
			assume edi: ptr _IMAGE_DOS_HEADER
			; 调整esi指针指向PE文件头
			mov esi, [edi].e_lfanew
			add esi, edi
			assume esi: ptr _IMAGE_NT_HEADERS

			mov eax, [esi].OptionalHeader.DataDirectory[sizeof _IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress
			mov edx, [esi].OptionalHeader.DataDirectory[sizeof _IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IAT].isize
			add eax, edi
			mov lpAddress, eax
			mov dwSize, edx
			invoke VirtualProtect, lpAddress, dwSize, PAGE_READWRITE, addr lpflOldProtect

			mov esi, [esi].OptionalHeader.DataDirectory[sizeof _IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			add esi, edi
			assume esi: ptr IMAGE_IMPORT_DESCRIPTOR
			.while [esi].FirstThunk != 0
				mov ecx, [esi].Name1
				add ecx, edi
				invoke EncryptName, ecx
				.if eax == 0D0ED5937h			; KERNEL32.dll
					mov ebx, [esi].Characteristics
					mov esi, [esi].FirstThunk
					add ebx, edi
					add esi, edi
					assume ebx: ptr IMAGE_THUNK_DATA
					.while [ebx].u1.Function != 0
						mov eax, [ebx].u1.Function
						assume eax: ptr IMAGE_IMPORT_BY_NAME
						lea eax, [eax].Name1
						assume eax: nothing
						add eax, edi
						invoke EncryptName, eax
						.if eax == 4320C21Ch		; fn_GetProcAddress
							;DebugOut "DllEntry : [Hook][GetProcAddress]"
							mov dword ptr [esi], offset fn_GetProcAddress
						.elseif eax == 399C8D96h	; fn_VirtualAlloc
							;DebugOut "DllEntry : [Hook][VirtualAlloc]"
							mov dword ptr [esi], offset fn_VirtualAlloc
						.endif
						add ebx, sizeof IMAGE_THUNK_DATA
						add esi, sizeof IMAGE_THUNK_DATA
					.endw
					assume ebx: nothing
					.break
				.endif
				add esi, sizeof IMAGE_IMPORT_DESCRIPTOR
			.endw
			assume esi: nothing

			invoke VirtualProtect, lpAddress, dwSize, lpflOldProtect, addr lpflOldProtect
		.endif
		assume edi: nothing
	;.elseif fdwReason == DLL_PROCESS_DETACH
	;.elseif fdwReason == DLL_THREAD_ATTACH
	;.elseif fdwReason == DLL_THREAD_DETACH
	.endif
	popad

	mov eax, TRUE
	ret
DllEntry endp

HideModule proc near uses ecx

	;DebugOut "HideModule : [curr_hModule][0x%.8X]", curr_hModule
	assume fs:nothing							;打开FS寄存器
	mov eax, fs:[30h]							;得到PEB结构地址
	assume eax: ptr PEB
	mov eax, [eax].Ldr							;得到PEB_LDR_DATA结构地址
	assume eax: ptr PEB_LDR_DATA
	mov eax, [eax].InMemoryOrderModuleList.Flink	;InMemoryOrderModuleList
	assume eax: ptr LDR_MODULE
	mov ecx, curr_hModule
	.repeat
		mov eax, [eax].InMemoryOrderModuleList.Flink
		assume eax: ptr LDR_MODULE
	.until [eax].BaseAddress == ecx
	mov eax, [eax].BaseDllName.Buffer
	assume eax: ptr PWSTR
	mov byte ptr [eax], 5Fh						; '_LEDLG.dll'

	assume eax: nothing

	ret
HideModule endp

EncryptName proc near uses ecx edx, lpProcName:LPCSTR

	;DebugOut "EncryptName : [lpProcName][%hs]", lpProcName
	xor eax, eax
	mov ecx, lpProcName
	.while byte ptr [ecx] != 0
		mov dl, [ecx]
		movsx edx, dl
		or edx, 20h
		add eax, edx
		rol eax, 0Dh
		inc ecx
	.endw

	ret
EncryptName endp

rpl_PublicKey proc near uses ecx edx edi, lpMem:LPVOID

	mov ecx, lpMem
	.if vax_hMem && lpMem && byte ptr [ecx] == 'x'
		;DebugOut "rpl_PublicKey : [lpMem][0x%.8X][%hs]", lpMem, lpMem
		;DebugOut "rpl_PublicKey : [vax_hMem][0x%.8X],[vax_dwSize][0x%.8X]", vax_hMem, vax_dwSize

		mov edi, vax_hMem
		mov edx, vax_dwSize
		.repeat
			.if byte ptr [edi] == '4'
				.if !rv(szcmpi, edi, offset oPublicKeyX, 0Bh)
					;DebugOut "rpl_PublicKey : [oPublicKeyX][0x%.8X][%.80hs]", edi, edi
					inc vax_index
					invoke szcopy, edi, offset cPublicKeyX
					add edi, 50h
				.endif
			.endif
			.if byte ptr [edi] == '1'
				.if !rv(szcmpi, edi, offset oPublicKeyY, 0Bh)
					;DebugOut "rpl_PublicKey : [oPublicKeyY][0x%.8X][%.80hs]", edi, edi
					inc vax_index
					invoke szcopy, edi, offset cPublicKeyY
					.break
				.endif
			.endif
			inc edi
			dec edx
		.until edx < 50h

		mov vax_hMem, 0
		mov vax_dwSize, 0
	.endif

	ret
rpl_PublicKey endp

rem_HookModule proc near uses ecx edx ebx esi edi
LOCAL lpAddress:DWORD
LOCAL lpflOldProtect:DWORD

	;DebugOut "rem_HookModule : [vax_hModule][0x%.8X]", vax_hModule
	mov edx, vax_hModule
	; 检测PE文件是否有效
	assume edx: ptr _IMAGE_DOS_HEADER
	; 调整esi指针指向PE文件头
	mov ecx, [edx].e_lfanew
	assume ecx: ptr _IMAGE_NT_HEADERS

	mov edi, [edx+[ecx].OptionalHeader.DataDirectory[sizeof _IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress]
	mov esi, [edx+[ecx].OptionalHeader.DataDirectory[sizeof _IMAGE_DATA_DIRECTORY*IMAGE_DIRECTORY_ENTRY_IAT].isize]
	add edi, edx
	mov lpAddress, edi
	invoke VirtualProtect, lpAddress, esi, PAGE_READWRITE, addr lpflOldProtect

	mov eax, edi
	lea ecx, dword ptr [eax+esi]
	.if eax < ecx
		mov edx, dword ptr [_imp__VirtualAlloc@16]
		mov ebx, dword ptr [_imp__GetProcAddress@8]
		.repeat
			.if dword ptr [eax] == offset fn_VirtualAlloc
				;DebugOut "rem_HookModule : [Remove][fn_VirtualAlloc]"
				mov dword ptr [eax], edx
			.elseif dword ptr [eax] == offset fn_GetProcAddress
				;DebugOut "rem_HookModule : [Remove][fn_GetProcAddress]"
				mov dword ptr [eax], ebx
			.endif
			add eax, 4
		.until eax >= ecx
	.endif

	invoke VirtualProtect, lpAddress, esi, lpflOldProtect, addr lpflOldProtect

	assume ecx: nothing
	assume edx: nothing

	;DebugOut "rem_HookModule : [vax_lpMem][0x%.8X]", vax_lpMem
	mov esi, vax_lpMem
	mov lpAddress, esi
	.if esi
		; 检测PE文件是否有效
		assume esi: ptr _IMAGE_DOS_HEADER
		; 调整esi指针指向PE文件头
		mov edi, [esi].e_lfanew
		add edi, esi
		assume edi: ptr _IMAGE_NT_HEADERS
		movzx ebx, [edi].FileHeader.SizeOfOptionalHeader
		mov ecx, [ebx+[edi].OptionalHeader.Win32VersionValue]
		add ecx, esi
		invoke VirtualProtect, ecx, dword ptr [ebx+[edi].OptionalHeader.MajorSubsystemVersion], PAGE_READWRITE, addr lpflOldProtect

		mov eax, [ebx+[edi].OptionalHeader.Win32VersionValue]
		mov ecx, dword ptr [ebx+[edi].OptionalHeader.MajorSubsystemVersion]
		add eax, esi
		add ecx, eax
		.if eax < ecx
			mov edx, dword ptr [_imp__LoadLibraryA@4]
			mov ebx, dword ptr [_imp__HeapAlloc@12]
			mov esi, dword ptr [_imp__HeapFree@12]
			.repeat
				.if dword ptr [eax] == offset fn_LoadLibraryA
					;DebugOut "rem_HookModule : [Remove][fn_LoadLibraryA]"
					mov dword ptr [eax], edx
				.elseif dword ptr [eax] == offset fn_HeapAlloc
					;DebugOut "rem_HookModule : [Remove][fn_HeapAlloc]"
					mov dword ptr [eax], ebx
				.elseif dword ptr [eax] == offset fn_HeapFree
					;DebugOut "rem_HookModule : [Remove][fn_HeapFree]"
					mov dword ptr [eax], esi
				.endif
				add eax, 4
			.until eax >= ecx
			mov esi, lpAddress
			movzx ebx, [edi].FileHeader.SizeOfOptionalHeader
		.endif

		mov ecx, [ebx+[edi].OptionalHeader.Win32VersionValue]
		add ecx, esi
		invoke VirtualProtect, ecx, dword ptr [ebx+[edi].OptionalHeader.MajorSubsystemVersion], lpflOldProtect, addr lpflOldProtect

		assume esi: nothing
		assume edi: nothing

		mov eax, TRUE
	.else
		mov eax, FALSE
	.endif

	ret
rem_HookModule endp

fn_LoadLibraryA proc lpLibFileName:LPCSTR
LOCAL hModule:HMODULE

	pushad
	;DebugOut "fn_LoadLibraryA : [%hs]", lpLibFileName
	mov hModule, rv(LoadLibrary, lpLibFileName)

	.if eax == curr_hModule
		invoke FreeLibrary, eax
		invoke rem_HookModule
		.if eax
			invoke HideModule
		.endif
		mov eax, ole_hModule
		mov hModule, eax
	.endif
	popad

	mov eax, hModule
	ret
fn_LoadLibraryA endp

fn_GetProcAddress proc hModule:HMODULE, lpProcName:LPCSTR
LOCAL fpAddr:FARPROC

	pushad
	mov fpAddr, rv(GetProcAddress, hModule, lpProcName)

	.if fpAddr && lpProcName > 0FFFFh
		;DebugOut "fn_GetProcAddress : [%hs]", lpProcName
		invoke EncryptName, lpProcName
		.if eax == 0FEECC773h		; fn_LoadLibraryA
			;DebugOut "fn_GetProcAddress : [Hook][LoadLibraryA]"
			mov fpAddr, offset fn_LoadLibraryA
		.elseif eax == 0D7E8FBC6h	; fn_HeapAlloc
			;DebugOut "fn_GetProcAddress : [Hook][HeapAlloc]"
			mov fpAddr, offset fn_HeapAlloc
		.elseif eax == 0C28581E4h	; fn_HeapFree
			;DebugOut "fn_GetProcAddress : [Hook][HeapFree]"
			mov fpAddr, offset fn_HeapFree
		.endif
	.endif
	popad

	mov eax, fpAddr
	ret
fn_GetProcAddress endp

fn_VirtualAlloc proc lpAddress:LPVOID, dwSize:DWORD, flAllocationType:DWORD, flProtect:DWORD
LOCAL lpMem:LPVOID

	pushad
	mov lpMem, rv(VirtualAlloc, lpAddress, dwSize, flAllocationType, flProtect)
	;DebugOut "fn_VirtualAlloc : [0x%.8X]", lpMem

	.if !vax_lpMem && eax
		mov vax_lpMem, eax
	.endif
	popad

	mov eax, lpMem
	ret
fn_VirtualAlloc endp

fn_HeapAlloc proc hHeap:HANDLE, dwFlags:DWORD, dwBytes:DWORD
LOCAL icmpbuf:LPVOID

	pushad
	mov icmpbuf, rv(HeapAlloc, hHeap, dwFlags, dwBytes)
	;DebugOut "fn_HeapAlloc : [0x%.8X]", icmpbuf

	.if !vax_index && icmpbuf && dwBytes == 0FFFFh
		mov vax_hMem, eax
		mov eax, dwBytes
		mov vax_dwSize, eax
	.endif
	popad

	mov eax, icmpbuf
	ret
fn_HeapAlloc endp

fn_HeapFree proc hHeap:HANDLE, dwFlags:DWORD, lpMem:LPVOID
LOCAL bResult:BOOL

	pushad
	;DebugOut "fn_HeapFree : [0x%.8X]", lpMem
	invoke rpl_PublicKey, lpMem
	mov bResult, rv(HeapFree, hHeap, dwFlags, lpMem)
	popad

	mov eax, bResult
	ret
fn_HeapFree endp

;#########################################################################

End DllEntry
