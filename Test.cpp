 //viz https://en.m.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files


struct DOS_Header 
 {
// short is 2 bytes, long is 4 bytes
     char signature[2] = { 'M', 'Z' };
     short lastsize;
     short nblocks;
     short nreloc;
     short hdrsize;
     short minalloc;
     short maxalloc;
     void *ss; // 2 byte value
     void *sp; // 2 byte value
     short checksum;
     void *ip; // 2 byte value
     void *cs; // 2 byte value
     short relocpos;
     short noverlay;
     short reserved1[4];
     short oem_id;
     short oem_info;
     short reserved2[10];
     long  e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
 }
struct COFFHeader
 {
    short Machine;
/*urcuje pro jaký pocitac je aplikace určena
Hodnota	Procesor
0x14c	Intel 386
0x8664	x64
0x162	MIPS R3000
0x168	MIPS R10000
0x169	MIPS little endian WCI v2
0x183	old Alpha AXP
0x184	Alpha AXP
0x1a2	Hitachi SH3
0x1a3	Hitachi SH3 DSP
0x1a6	Hitachi SH4
0x1a8	Hitachi SH5
0x1c0	ARM little endian
0x1c2	Thumb
0x1c4	ARMv7 (Thumb-2)
0x1d3	Matsushita AM33
0x1f0	PowerPC little endian
0x1f1	PowerPC with floating point support
0x1f2	PowerPC 64-bit little endian
0x200	Intel IA64
0x266	MIPS16
0x268	Motorola 68000 series
0x284	Alpha AXP 64-bit
0x366	MIPS with FPU
0x466	MIPS16 with FPU
0xebc	EFI Byte Code
0x8664	AMD AMD64
0x9041	Mitsubishi M32R little endian
0xaa64	ARM64 little endian
0xc0ee	clr pure MSIL

*/
    short NumberOfSections;
/*
Počet sekci které jsou definovány na konci PE záhlaví 
*/
    long TimeDateStamp;
/*
32bit čas ve kterém byla tato hlavička vygenerovana, použití při procesu "Binding"
*/
    long PointerToSymbolTable;
    long NumberOfSymbols;
    short SizeOfOptionalHeader;
/*
 ukazuje jak dlouhá je volitelná hlavička PE(následuje po hLavicce COFF)
*/
    short Characteristics;
/*
Bitové příznaky určující vlastnosti souboru

Jméno konstanty.             Bity / Maska.      Popis 
IMAGE_FILE_RELOCS_STRIPPED	1 / 0x0001	Relocation information was stripped from file
IMAGE_FILE_EXECUTABLE_IMAGE	2 / 0x0002	Soubor je spustitelný 
IMAGE_FILE_LINE_NUMS_STRIPPED	3 / 0x0004	COFF line numbers were stripped from file
IMAGE_FILE_LOCAL_SYMS_STRIPPED	4 / 0x0008	COFF symbol table entries were stripped from file
IMAGE_FILE_AGGRESIVE_WS_TRIM	5 / 0x0010	Aggressively trim the working set(obsolete)
IMAGE_FILE_LARGE_ADDRESS_AWARE	6 / 0x0020	The application can handle addresses greater than 2 GB
IMAGE_FILE_BYTES_REVERSED_LO	8 / 0x0080	The bytes of the word are reversed(obsolete)
IMAGE_FILE_32BIT_MACHINE	9 / 0x0100	The computer supports 32-bit words
IMAGE_FILE_DEBUG_STRIPPED	10 / 0x0200	Debugging information was removed and stored separately in another file
IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	11 / 0x0400	If the image is on removable media, copy it to and run it from the swap file
IMAGE_FILE_NET_RUN_FROM_SWAP	12 / 0x0800	If the image is on the network, copy it to and run it from the swap file
IMAGE_FILE_SYSTEM	13 / 0x1000	The image is a system file
IMAGE_FILE_DLL	14 / 0x2000	The image is a DLL file
IMAGE_FILE_UP_SYSTEM_ONLY	15 / 0x4000	The image should only be ran on a single processor computer
IMAGE_FILE_BYTES_REVERSED_HI	16 / 0x8000	The bytes of the word are reversed(obsolete)

*/
 }

struct PEOptHeader
 {
/* 64 bit version of the PE Optional Header also known as IMAGE_OPTIONAL_HEADER64
char is 1 byte
short is 2 bytes
long is 4 bytes
long long is 8 bytes
*/
    short signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. 
    char MajorLinkerVersion; 
    char MinorLinkerVersion;
    long SizeOfCode;
    long SizeOfInitializedData;
    long SizeOfUninitializedData;
    long AddressOfEntryPoint;  //The RVA of the code entry point
    long BaseOfCode;
    /*The next 21 fields are an extension to the COFF optional header format*/
    long long ImageBase;
    long SectionAlignment;
    long FileAlignment;
    short MajorOSVersion;
    short MinorOSVersion;
    short MajorImageVersion;
    short MinorImageVersion;
    short MajorSubsystemVersion;
    short MinorSubsystemVersion;
    long Win32VersionValue;
    long SizeOfImage;
    long SizeOfHeaders;
    long Checksum;
    short Subsystem;
    short DLLCharacteristics;
    long long SizeOfStackReserve;
    long long SizeOfStackCommit;
    long long SizeOfHeapReserve;
    long long SizeOfHeapCommit;
    long LoaderFlags;
    long NumberOfRvaAndSizes;
    data_directory DataDirectory[NumberOfRvaAndSizes];     //Can have any number of elements, matching the number in NumberOfRvaAndSizes.
 }    

  struct PEOptHeader
 {
/* 32 bit version of the PE Optional Header also known as IMAGE_OPTIONAL_HEADER
char is 1 byte
short is 2 bytes
long is 4 bytes
*/
    short signature; //decimal number 267 for 32 bit, 523 for 64 bit, and 263 for a ROM image. 
    char MajorLinkerVersion; 
    char MinorLinkerVersion;
    long SizeOfCode;
    long SizeOfInitializedData;
    long SizeOfUninitializedData;
    long AddressOfEntryPoint;  //The RVA of the code entry point
    long BaseOfCode;
    long BaseOfData;
    /*The next 21 fields are an extension to the COFF optional header format*/
    long ImageBase;
    long SectionAlignment;
    long FileAlignment;
    short MajorOSVersion;
    short MinorOSVersion;
    short MajorImageVersion;
    short MinorImageVersion;
    short MajorSubsystemVersion;
    short MinorSubsystemVersion;
    long Win32VersionValue;
    long SizeOfImage;
    long SizeOfHeaders;
    long Checksum;
    short Subsystem;
    short DLLCharacteristics;
    long SizeOfStackReserve;
    long SizeOfStackCommit;
    long SizeOfHeapReserve;
    long SizeOfHeapCommit;
    long LoaderFlags;
    long NumberOfRvaAndSizes;
    data_directory DataDirectory[NumberOfRvaAndSizes];     //Can have any number of elements, matching the number in NumberOfRvaAndSizes.
 }                                        //However, it is always 16 in PE files

/*
long is 4 bytes
*/
 struct data_directory
 { 
    long VirtualAddress;
    long Size;
 }

struct IMAGE_SECTION_HEADER 
 {
// short is 2 bytes
// long is 4 bytes
  char  Name[IMAGE_SIZEOF_SHORT_NAME]; // IMAGE_SIZEOF_SHORT_NAME is 8 bytes
  union {
    long PhysicalAddress;
    long VirtualSize;
  } Misc;
  long  VirtualAddress;
  long  SizeOfRawData;
  long  PointerToRawData;
  long  PointerToRelocations;
  long  PointerToLinenumbers;
  short NumberOfRelocations;
  short NumberOfLinenumbers;
  long  Characteristics;
 }

struct IMAGE_EXPORT_DIRECTORY {
	long Characteristics;
	long TimeDateStamp;
	short MajorVersion;
	short MinorVersion;
	long Name;
	long Base;
	long NumberOfFunctions;
	long NumberOfNames;
	long *AddressOfFunctions;
	long *AddressOfNames;
	long *AddressOfNameOrdinals;
}

struct IMAGE_IMPORT_DESCRIPTOR {
	long *OriginalFirstThunk;
	long TimeDateStamp;
	long ForwarderChain;
	long Name;
	long *FirstThunk;
}

struct IMAGE_IMPORT_BY_NAME {
	short Hint;
	char Name[1];
}
