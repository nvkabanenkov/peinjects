#ifndef PEINJECTS_PE_H_
#define PEINJECTS_PE_H_

#include <cstdint>
#include <type_traits>

#define IMAGE_DOS_SIGNATURE                 0x5A4D
#define IMAGE_NT_SIGNATURE                  0x00004550

#define IMAGE_FILE_MACHINE_I386              0x014c
#define IMAGE_FILE_MACHINE_AMD64             0x8664

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor

namespace peinjects {
    namespace pe {

        struct ImageDosHeader {
            std::uint16_t e_magic;
            std::uint16_t e_cblp;
            std::uint16_t e_cp;
            std::uint16_t e_crlc;
            std::uint16_t e_cparhdr;
            std::uint16_t e_minalloc;
            std::uint16_t e_maxalloc;
            std::uint16_t e_ss;
            std::uint16_t e_sp;
            std::uint16_t e_csum;
            std::uint16_t e_ip;
            std::uint16_t e_cs;
            std::uint16_t e_lfarlc;
            std::uint16_t e_ovno;
            std::uint16_t e_res[4];
            std::uint16_t e_oemid;
            std::uint16_t e_oeminfo;
            std::uint16_t e_res2[10];
            std::uint32_t e_lfanew;
        };

        struct ImageFileHeader {
            std::uint16_t Machine;
            std::uint16_t NumberOfSections;
            std::uint32_t TimeDateStamp;
            std::uint32_t PointerToSymbolTable;
            std::uint32_t NumberOfSymbols;
            std::uint16_t SizeOfOptionalHeader;
            std::uint16_t Characteristics;
        };

        struct ImageDataDirectory {
            std::uint32_t   VirtualAddress;
            std::uint32_t   Size;
        };

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

        struct ImageOptionalHeader32 {
            std::uint16_t    Magic;
            std::uint8_t    MajorLinkerVersion;
            std::uint8_t    MinorLinkerVersion;
            std::uint32_t   SizeOfCode;
            std::uint32_t   SizeOfInitializedData;
            std::uint32_t   SizeOfUninitializedData;
            std::uint32_t   AddressOfEntryPoint;
            std::uint32_t   BaseOfCode;
            std::uint32_t   BaseOfData;
            std::uint32_t   ImageBase;
            std::uint32_t   SectionAlignment;
            std::uint32_t   FileAlignment;
            std::uint16_t    MajorOperatingSystemVersion;
            std::uint16_t    MinorOperatingSystemVersion;
            std::uint16_t    MajorImageVersion;
            std::uint16_t    MinorImageVersion;
            std::uint16_t    MajorSubsystemVersion;
            std::uint16_t    MinorSubsystemVersion;
            std::uint32_t   Win32VersionValue;
            std::uint32_t   SizeOfImage;
            std::uint32_t   SizeOfHeaders;
            std::uint32_t   CheckSum;
            std::uint16_t    Subsystem;
            std::uint16_t    DllCharacteristics;
            std::uint32_t   SizeOfStackReserve;
            std::uint32_t   SizeOfStackCommit;
            std::uint32_t   SizeOfHeapReserve;
            std::uint32_t   SizeOfHeapCommit;
            std::uint32_t   LoaderFlags;
            std::uint32_t   NumberOfRvaAndSizes;
            ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        };

        struct ImageOptionalHeader64 {
            std::uint16_t        Magic;
            std::uint8_t        MajorLinkerVersion;
            std::uint8_t        MinorLinkerVersion;
            std::uint32_t       SizeOfCode;
            std::uint32_t       SizeOfInitializedData;
            std::uint32_t       SizeOfUninitializedData;
            std::uint32_t       AddressOfEntryPoint;
            std::uint32_t       BaseOfCode;
            std::uint64_t   ImageBase;
            std::uint32_t       SectionAlignment;
            std::uint32_t       FileAlignment;
            std::uint16_t        MajorOperatingSystemVersion;
            std::uint16_t        MinorOperatingSystemVersion;
            std::uint16_t        MajorImageVersion;
            std::uint16_t        MinorImageVersion;
            std::uint16_t        MajorSubsystemVersion;
            std::uint16_t        MinorSubsystemVersion;
            std::uint32_t       Win32VersionValue;
            std::uint32_t       SizeOfImage;
            std::uint32_t       SizeOfHeaders;
            std::uint32_t       CheckSum;
            std::uint16_t        Subsystem;
            std::uint16_t        DllCharacteristics;
            std::uint64_t   SizeOfStackReserve;
            std::uint64_t   SizeOfStackCommit;
            std::uint64_t   SizeOfHeapReserve;
            std::uint64_t   SizeOfHeapCommit;
            std::uint32_t       LoaderFlags;
            std::uint32_t       NumberOfRvaAndSizes;
            ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
        };

        struct ImageNtHeaders32 {
            std::uint32_t Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader32 OptionalHeader;
        };

        struct ImageNtHeaders64 {
            std::uint32_t Signature;
            ImageFileHeader FileHeader;
            ImageOptionalHeader64 OptionalHeader;
        };

#define IMAGE_SIZEOF_SHORT_NAME              8

        struct ImageSectionHeader {
            std::uint8_t    Name[IMAGE_SIZEOF_SHORT_NAME];
            union {
                std::uint32_t   PhysicalAddress;
                std::uint32_t   VirtualSize;
            } Misc;
            std::uint32_t   VirtualAddress;
            std::uint32_t   SizeOfRawData;
            std::uint32_t   PointerToRawData;
            std::uint32_t   PointerToRelocations;
            std::uint32_t   PointerToLinenumbers;
            std::uint16_t    NumberOfRelocations;
            std::uint16_t    NumberOfLinenumbers;
            std::uint32_t   Characteristics;
        };


        struct ImageImportDescriptor {
            union {
                std::uint32_t   Characteristics;            // 0 for terminating null import descriptor
                std::uint32_t   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
            };
            std::uint32_t   TimeDateStamp;                  // 0 if not bound,
                                                    // -1 if bound, and real date\time stamp
                                                    //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                                    // O.W. date/time stamp of DLL bound to (Old BIND)

            std::uint32_t   ForwarderChain;                 // -1 if no forwarders
            std::uint32_t   Name;
            std::uint32_t   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
        };

        struct ImageImportLookupTable32 {
            std::uint16_t Low : 16;
            std::uint16_t High : 15;
            std::uint16_t OrdinalNameFlag : 1;
        };
        static_assert(sizeof(ImageImportLookupTable32) == 4);

        struct ImageImportLookupTable64 {
            std::uint32_t Low : 32;
            std::uint32_t High : 31;
            std::uint32_t OrdinalNameFlag : 1;
        };
        static_assert(sizeof(ImageImportLookupTable64) == 8);


    } // namespace pe
} // namespace peinjects

#endif // PEINJECTS_PE_H_
