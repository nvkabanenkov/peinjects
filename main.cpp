#include <iostream>
#include <fstream>
#include <string>
#include "pe.h"
#include "peinjects.h"

int main() {
    std::fstream file("calc.exe", std::ios_base::binary | std::ios_base::in);
    file.seekg(0, file.end);
    std::size_t len = file.tellg();
    file.seekg(0, file.beg);

    char* buf = new char[len];
    file.read(buf, len);
    file.close();

    peinjects::PeInjects pe(buf);
    auto dd_import = pe.GetNtHeaders64()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    auto import_descriptor = reinterpret_cast<peinjects::pe::ImageImportDescriptor*>(buf + pe.RvaToRaw(dd_import.VirtualAddress));
    peinjects::pe::ImageImportDescriptor* kernel32 = nullptr;

    while (import_descriptor->Characteristics != 0) {
        if (std::string(reinterpret_cast<char*>(buf + pe.RvaToRaw(import_descriptor->Name))) == "KERNEL32.dll")
            kernel32 = import_descriptor;
        ++import_descriptor;
    }

    std::uint32_t offset = pe.RvaToRaw(kernel32->OriginalFirstThunk);
    std::uint32_t offset_iat = pe.RvaToRaw(kernel32->FirstThunk);
    std::uint32_t LoadLibraryExA_rva, GetProcAddress_rva;

    while(*(std::int64_t*)(buf + offset) != 0) {
        //bool by_ordinal = (bool)(*(std::int64_t*)(buf + offset) & 0x8000000000000000);
        std::uint32_t hint_rva = *(std::uint32_t*)(buf + offset);
        std::string hint((char*)(buf + pe.RvaToRaw(hint_rva) + 2));
        if (hint == "GetProcAddress")
            GetProcAddress_rva = pe.RawToRva(offset_iat);
        if (hint == "LoadLibraryExA")
            LoadLibraryExA_rva = pe.RawToRva(offset_iat);
        offset += pe.IsX86() ? 4 : 8;
        offset_iat += pe.IsX86() ? 4 : 8;
    }

    delete[] buf;

    return 0;
}
