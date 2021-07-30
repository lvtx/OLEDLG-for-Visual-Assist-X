;#########################################################################
;		Include files

	include windows.inc
	include kernel32.inc
	include user32.inc

;#########################################################################
;		Libraries

	includelib kernel32.lib
	includelib user32.lib

;#########################################################################
;		RadASM Add In Include

	;include C:\RadASM\Masm\Inc\radasm.inc
	include C:\masm32\macros\macros.asm

;#########################################################################
;		VKim's Debug

	include C:\RadASM\masm\inc\debug.inc
	includelib C:\RadASM\masm\lib\debug.lib

	DBGWIN_DEBUG_ON = 1	; include debug info into the program
	DBGWIN_EXT_INFO = 0		; include extra debug info into the program

;#########################################################################
;		API Table

_DATA segment
	externdef c _imp__LoadLibraryA@4:ptr pr1
	LoadLibrary equ <_imp__LoadLibraryA@4>
	externdef c _imp__GetProcAddress@8:ptr pr2
	;GetProcAddress equ <_imp__GetProcAddress@8>
	externdef c _imp__VirtualAlloc@16:ptr pr4
	;VirtualAlloc equ <_imp__VirtualAlloc@16>
	externdef c _imp__HeapAlloc@12:ptr pr3
	;HeapAlloc equ <_imp__HeapAlloc@12>
	externdef c _imp__HeapFree@12:ptr pr3
	;HeapFree equ <_imp__HeapFree@12>
	wsprintfAproto typedef PROTO C :DWORD,:DWORD,:VARARG
	externdef c _imp__wsprintfA:ptr wsprintfAproto
	wsprintf equ <_imp__wsprintfA>
_DATA ends

; 其中包括常量定义。这些常量在程序运行过程中是不能更改的。 应用程序并不需要以上所有的三个"分段"， 可以根据需要进行定义。
.CONST

	;strVaxNameA				db	"C:\Users\lvtx\AppData\Local\Microsoft\VisualStudio\16.0_fff0df99\Extensions\gw1vs44c.wba\VA_X", 0
	strVaxName				db	"VA_X", 0
	strKernel					db	"kernel32.dll", 0
	strLoadLibrary			db	"LoadLibraryA",0
	strGetProcAddress			db	"GetProcAddress", 0
	strVirtualAlloc				db	"VirtualAlloc", 0
	strHeapAlloc				db	"HeapAlloc", 0
	strHeapFree				db	"HeapFree", 0
	strLoadLib				db	"\OLEDLG.dll", 0

	oPublicKeyX				db "4065234961,2221233238252903594850812155620126,3175203956977476891557515669668792", 0
	oPublicKeyY				db "1329115615,9626603984703850283064885442292035,3463780848057510008753765087591958", 0
	cPublicKeyX				db "2127088620,2558213661223504372788100802238141,2694097057723490910395353919176313", 0
	cPublicKeyY				db "2127088620,8809976404932220599325753072055172,1929719295914332726580392022338415", 0

; 其中包括已初始化的数据。
.DATA

;#########################################################################
;		reference

; 其中包括未初始化的数据。比如有时您仅想预先分配一些内存但并不想指定初始值。
; 使用未初始化的数据的优点是它不占据可执行文件的大小，如：若您要在 .DATA? 段中分配10，000字节的空间，您的可执行文件的大小无须增加10，000字节，而仅仅是要告诉编译器在装载可执行文件时分配所需字节。
.DATA?

	hInstance					dd	?	;Dll's module handle
	lpHandles				dd	?	;Pointer to handles struct
	lpProc					dd	?	;Pointer to proc struct
	lpData					dd	?	;Pointer to data struct
	hOut					dd	?	;Handle of output window
	IDAddIn					dd	?	;Unique ID for this AddIn

; Section 2. (virtual address 00002000)
; Virtual size                  : 0000001C (     28.)
; Section size in file          : 00000000 (      0.)
; Offset to raw data for section: 00000000
; Flags C0000040: Data Readable Writable
; Alignment     : default

; Segment type: Pure data
; Segment permissions: Read/Write
;_data segment para public 'DATA' use32
;assume cs:_data
;org 20002000h
	vax_hMem				dd	?
	vax_dwSize				dd	?
	ole_hModule				dd	?
	vax_index					dd	?
	vax_lpMem				dd	?
	vax_hModule				dd	?
	curr_hModule				dd	?
;_data ends

; 这是代码"分段"。
.CODE

;#########################################################################
;		Prototypes

	HideModule PROTO
	EncryptName PROTO lpProcName:LPCSTR
	rpl_PublicKey PROTO lpMem:LPVOID
	rem_HookModule PROTO
	fn_LoadLibraryA PROTO lpLibFileName:LPCSTR
	fn_GetProcAddress PROTO hModule:HMODULE,lpProcName:LPCSTR
	fn_VirtualAlloc PROTO lpAddress:LPVOID,dwSize:DWORD,flAllocationType:DWORD,flProtect:DWORD
	fn_HeapAlloc PROTO hHeap:HANDLE,dwFlags:DWORD,dwBytes:DWORD
	fn_HeapFree PROTO hHeap:HANDLE,dwFlags:DWORD,lpMem:LPVOID

	memcpy PROTO near, target:ptr DWORD, source:ptr DWORD, count:DWORD
	szcmpi PROTO near, src:DWORD, dst:DWORD, ln:DWORD
	szlen PROTO near, string:ptr DWORD
	szcopy PROTO near, src:DWORD,dst:DWORD

;#########################################################################
;		string procs

memcpy  proc near uses ecx esi edi, target:ptr DWORD, source:ptr DWORD, count:DWORD

	mov esi, source
	mov edi, target
	mov ecx, count
	rep movsb

	ret
memcpy  endp

szcmpi proc near uses ebx ecx edx esi edi, src:DWORD, dst:DWORD, ln:DWORD

	mov eax, ln
	mov edi, dst
	mov esi, src
	sub ecx, ecx                    ; zero ecx as index

	.repeat
		movzx ebx, byte ptr [esi+ecx]
		movzx edx, byte ptr [edi+ecx]
		.if ebx != edx
			.break
		.endif
		inc ecx
		dec eax
	.until !eax

	ret
szcmpi endp

szlen proc near uses ecx edi, string:ptr DWORD

	mov edi, string
	xor ecx, ecx
	dec ecx
	xor eax, eax
	repne scasb
	not ecx
	dec ecx
	mov eax, ecx

	ret
szlen  endp

szcopy proc near uses ebx, src:DWORD, dst:DWORD

	mov ebx, rv(szlen, dst)
	inc ebx
	invoke memcpy, src, dst, ebx

	ret
szcopy endp

;#########################################################################
;		Output Window procs

DebugOut MACRO lpFmt:req, args:VARARG
LOCAL buffer, sym
.DATA
	sym db "[OLEDLG] "
	db lpFmt, 0
	buffer db 255 dup(0)
.CODE
	pushad
	ifnb <args>
		invoke wsprintf, addr buffer, addr sym, args
		invoke OutputDebugString, addr buffer
	else
		invoke OutputDebugString, addr sym
	endif
	popad
ENDM