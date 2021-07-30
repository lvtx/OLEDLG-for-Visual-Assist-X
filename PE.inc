IMAGE_DIRECTORY_ENTRY_EXPORT			equ	0
IMAGE_DIRECTORY_ENTRY_IMPORT			equ	1
IMAGE_DIRECTORY_ENTRY_RESOURCE		equ	2
IMAGE_DIRECTORY_ENTRY_EXCEPTION		equ	3
IMAGE_DIRECTORY_ENTRY_SECURITY			equ	4
IMAGE_DIRECTORY_ENTRY_BASERELOC		equ	5
IMAGE_DIRECTORY_ENTRY_DEBUG			equ	6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT		equ	7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE	equ	7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR		equ	8
IMAGE_DIRECTORY_ENTRY_TLS				equ	9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG		equ	10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT	equ	11
IMAGE_DIRECTORY_ENTRY_IAT				equ	12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT	equ	13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	equ	14

IMAGE_NUMBEROF_DIRECTORY_ENTRIES		equ	16

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Unicode strings are counted 16-bit character strings. If they are
; NULL terminated, Length does not include trailing NULL.
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

IFNDEF UNICODE_STRING
	UNICODE_STRING STRUCT			; sizeof = 08h
		_Length						WORD		?					; 00h	len of string in bytes (not chars)
		MaximumLength				WORD		?					; 02h	len of Buffer in bytes (not chars)
		Buffer						PWSTR		?					; 04h	pointer to string
	UNICODE_STRING ENDS
	PUNICODE_STRING typedef	PTR UNICODE_STRING
ENDIF

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_DOS_HEADER)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_DOS_HEADER STRUCT			; sizeof = 40h								DOS .EXE header
	e_magic							WORD		?					; 00h	Magic number
	e_cblp							WORD		?					; 02h	Bytes on last page of file
	e_cp								WORD		?					; 04h	Pages in file
	e_crlc							WORD		?					; 06h	Relocations
	e_cparhdr						WORD		?					; 08h	Size of header in paragraphs
	e_minalloc						WORD		?					; 0Ah	Minimum extra paragraphs needed
	e_maxalloc						WORD		?					; 0Ch	Maximum extra paragraphs needed
	e_ss								WORD		?					; 0Eh	Initial (relative) SS value
	e_sp								WORD		?					; 10h	Initial SP value
	e_csum							WORD		?					; 12h	Checksum
	e_ip								WORD		?					; 14h	Initial IP value
	e_cs								WORD		?					; 16h	Initial (relative) CS value
	e_lfarlc							WORD		?					; 18h	File address of relocation table
	e_ovno							WORD		?					; 1Ah	Overlay number
	e_res							WORD	4 dup(?)					; 1Ch	Reserved words
	e_oemid							WORD		?					; 24h	OEM identifier (for e_oeminfo)
	e_oeminfo						WORD		?					; 26h	OEM information; e_oemid specific
	e_res2							WORD	10 dup(?)					; 28h	Reserved words
	e_lfanew							DWORD		?					; 3Ch	File address of new exe header
_IMAGE_DOS_HEADER ENDS
PIMAGE_DOS_HEADER typedef PTR _IMAGE_DOS_HEADER

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_DATA_DIRECTORY)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_DATA_DIRECTORY STRUCT		; sizeof = 08h
	VirtualAddress					DWORD      ?						; 00h
	isize								DWORD      ?						; 04h
_IMAGE_DATA_DIRECTORY ENDS
PIMAGE_DATA_DIRECTORY typedef PTR _IMAGE_DATA_DIRECTORY

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_FILE_HEADER)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_FILE_HEADER STRUCT			; sizeof = 14h
	Machine							WORD		?					; 00h
	NumberOfSections					WORD		?					; 02h
	TimeDateStamp					DWORD		?					; 04h
	PointerToSymbolTable				DWORD		?					; 08h
	NumberOfSymbols					DWORD		?					; 0Ch
	SizeOfOptionalHeader				WORD		?					; 10h
	Characteristics					WORD		?					; 12h
_IMAGE_FILE_HEADER ENDS
PIMAGE_FILE_HEADER typedef PTR _IMAGE_FILE_HEADER

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_OPTIONAL_HEADER32)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_OPTIONAL_HEADER32 STRUCT	; sizeof = E0h
	Magic							WORD		?					; 0000h
	MajorLinkerVersion				BYTE		?					; 0002h
	MinorLinkerVersion				BYTE		?					; 0003h
	SizeOfCode						DWORD		?					; 0004h
	SizeOfInitializedData				DWORD		?					; 0008h
	SizeOfUninitializedData				DWORD		?					; 000Ch
	AddressOfEntryPoint				DWORD		?					; 0010h
	BaseOfCode						DWORD		?					; 0014h
	BaseOfData						DWORD		?					; 0018h
	ImageBase						DWORD		?					; 001Ch
	SectionAlignment					DWORD		?					; 0020h
	FileAlignment						DWORD		?					; 0024h
	MajorOperatingSystemVersion		WORD		?					; 0028h
	MinorOperatingSystemVersion		WORD		?					; 002Ah
	MajorImageVersion				WORD		?					; 002Ch
	MinorImageVersion				WORD		?					; 002Eh
	MajorSubsystemVersion			WORD		?					; 0030h
	MinorSubsystemVersion			WORD		?					; 0032h
	Win32VersionValue				DWORD		?					; 0034h
	SizeOfImage						DWORD		?					; 0038h
	SizeOfHeaders					DWORD		?					; 003Ch
	CheckSum						DWORD		?					; 0040h
	Subsystem						WORD		?					; 0044h
	DllCharacteristics					WORD		?					; 0046h
	SizeOfStackReserve				DWORD		?					; 0048h
	SizeOfStackCommit				DWORD		?					; 004Ch
	SizeOfHeapReserve				DWORD		?					; 0050h
	SizeOfHeapCommit				DWORD		?					; 0054h
	LoaderFlags						DWORD		?					; 0058h
	NumberOfRvaAndSizes				DWORD		?					; 005Ch
	DataDirectory						_IMAGE_DATA_DIRECTORY	IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)	; 0060h
_IMAGE_OPTIONAL_HEADER32 ENDS
PIMAGE_OPTIONAL_HEADER32 typedef PTR _IMAGE_OPTIONAL_HEADER32

_IMAGE_OPTIONAL_HEADER  equ  <_IMAGE_OPTIONAL_HEADER32>

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_NT_HEADERS)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_NT_HEADERS STRUCT			; sizeof = F8h
	Signature							DWORD		?					; 00h
	FileHeader						_IMAGE_FILE_HEADER	<>			; 04h
	OptionalHeader					_IMAGE_OPTIONAL_HEADER	<>		; 18h
_IMAGE_NT_HEADERS ENDS
PIMAGE_NT_HEADERS typedef PTR _IMAGE_NT_HEADERS

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (IMAGE_SECTION_HEADER)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

_IMAGE_SECTION_HEADER STRUCT		; sizeof = 30h
	Name1							db	IMAGE_SIZEOF_SHORT_NAME dup(?)	; 00h
	union Misc
		PhysicalAddress				dd			?					; 08h
		VirtualSize					dd			?					; 0Ch
	ends
	VirtualAddress					dd			?					; 10h
	SizeOfRawData					dd			?					; 14h
	PointerToRawData					dd			?					; 18h
	PointerToRelocations				dd			?					; 1Ch
	PointerToLinenumbers				dd			?					; 20h
	NumberOfRelocations				dw			?					; 24h
	NumberOfLinenumbers				dw			?					; 28h
	Characteristics					dd			?					; 2Ch
_IMAGE_SECTION_HEADER ENDS

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
; Process Environment Block (PEB)
; located at 7FFDF000h (pointed by fs:[30] in user mode)
;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

PEB STRUCT							; sizeof = 1E8h
	InheritedAddressSpace				BYTE		?					; 0000h
	ReadImageFileExecOptions			BYTE		?					; 0001h
	BeingDebugged					BYTE		?					; 0002h
	SpareBool						BYTE		?					; 0003h
	Mutant							PVOID		?					; 0004h
	ImageBaseAddress				PVOID		?					; 0008h
	Ldr								PVOID		?					; 000Ch PTR PEB_LDR_DATA
	ProcessParameters					PVOID		?					; 0010h PTR RTL_USER_PROCESS_PARAMETERS
	SubSystemData					PVOID		?					; 0014h
	ProcessHeap						PVOID		?					; 0018h
	FastPebLock						PVOID		?					; 001Ch
	FastPebLockRoutine				PVOID		?					; 0020h
	FastPebUnlockRoutine				PVOID		?					; 0024h
	EnvironmentUpdateCount			DWORD		?					; 0028h
	KernelCallbackTable				PVOID		?					; 002Ch
	SystemReserved					DWORD	2 dup(?)					; 0030h
	FreeList							PVOID		?					; 0038h PTR PEB_FREE_BLOCK
	TlsExpansionCounter				DWORD		?					; 003Ch
	TlsBitmap						PVOID		?					; 0040h
	TlsBitmapBits						DWORD	2 dup(?)					; 0044h
	ReadOnlySharedMemoryBase		PVOID		?					; 004Ch
	ReadOnlySharedMemoryHeap		PVOID		?					; 0050h
	ReadOnlyStaticServerData			PVOID		?					; 0054h
	AnsiCodePageData					PVOID		?					; 0058h
	OemCodePageData				PVOID		?					; 005Ch
	UnicodeCaseTableData				PVOID		?					; 0060h
	NumberOfProcessors				DWORD		?					; 0064h
	NtGlobalFlag						DWORD		?					; 0068h
									DWORD		?					; 006Ch
	CriticalSectionTimeout				LARGE_INTEGER	<>				; 0070h
	HeapSegmentReserve				DWORD		?					; 0078h
	HeapSegmentCommit				DWORD		?					; 007Ch
	HeapDeCommitTotalFreeThreshold	DWORD		?					; 0080h
	HeapDeCommitFreeBlockThreshold	DWORD		?					; 0084h
	NumberOfHeaps					DWORD		?					; 0088h
	MaximumNumberOfHeaps			DWORD		?					; 008Ch
	ProcessHeaps						PVOID		?					; 0090h
	GdiSharedHandleTable				PVOID		?					; 0094h
	ProcessStarterHelper				PVOID		?					; 0098h
	GdiDCAttributeList					DWORD		?					; 009Ch
	LoaderLock						PVOID		?					; 00A0h
	OSMajorVersion					DWORD		?					; 00A4h
	OSMinorVersion					DWORD		?					; 00A8h
	OSBuildNumber					WORD		?					; 00ACh
	OSCSDVersion					WORD		?					; 00AEh
	OSPlatformId						DWORD		?					; 00B0h
	ImageSubsystem					DWORD		?					; 00B4h
	ImageSubsystemMajorVersion		DWORD		?					; 00B8h
	ImageSubsystemMinorVersion		DWORD		?					; 00BCh
	ImageProcessAffinityMask			DWORD		?					; 00C0h
	GdiHandleBuffer					DWORD	34 dup(?)					; 00C4h
	PostProcessInitRoutine				DWORD		?					; 014Ch
	TlsExpansionBitmap				PVOID		?					; 0150h
	TlsExpansionBitmapBits				DWORD	32 dup(?)					; 0154h
	SessionId						DWORD		?					; 01D4h
	AppCompatInfo					PVOID		?					; 01D8h
	CSDVersion						UNICODE_STRING	<>				; 01DCh
									DWORD		?					; 01E4h
PEB ENDS
PPEB typedef PTR PEB

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

PEB_LDR_DATA STRUCT					; sizeof = 24h
	_Length							DWORD		?					; 00h	original name Length
	Initialized							BYTE		?					; 04h
									db 	3 dup(?)						; 05h	padding
	SsHandle							PVOID		?					; 08h
	InLoadOrderModuleList				LIST_ENTRY	<>					; 0Ch	LDR_MODULE
	InMemoryOrderModuleList			LIST_ENTRY	<>					; 14h	LDR_MODULE
	InInitializationOrderModuleList		LIST_ENTRY	<>					; 1Ch	LDR_MODULE
PEB_LDR_DATA ENDS
PPEB_LDR_DATA typedef PTR PEB_LDR_DATA

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

LDR_MODULE STRUCT					; sizeof = 40h
	InMemoryOrderModuleList			LIST_ENTRY	<>					; 00h	代表按内存顺序构成的模块链表
	InInitializationOrderModuleList		LIST_ENTRY	<>					; 08h	代表按初始化顺序构成的模块链表
	BaseAddress						PVOID		?					; 10h	该模块的基地址
	EntryPoint						PVOID		?					; 14h	该模块的入口
	SizeOfImage						DWORD		?					; 18h	该模块的镜像大小
	FullDllName						UNICODE_STRING	<>				; 1Ch	包含路径的模块名
	BaseDllName						UNICODE_STRING	<>				; 24h	不包含路径的模块名
	Flags							DWORD		?					; 2Ch
	LoadCount						WORD		?					; 30h	该模块的引用计数
	TlsIndex							WORD		?					; 32h
	HashTableEntry					LIST_ENTRY	<>					; 34h
	TimeDateStamp					DWORD		?					; 3Ch
LDR_MODULE ENDS
PLDR_MODULE typedef PTR LDR_MODULE

;:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::