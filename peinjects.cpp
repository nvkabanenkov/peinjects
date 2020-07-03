#include <iostream>

#include "peinjects.h"

peinjects::PeInjects::PeInjects(void* pointer_to_pe)
{
    ptr_ = static_cast<char*>(pointer_to_pe);

    dos_hdr_ = reinterpret_cast<pe::ImageDosHeader*>(ptr_);

    if (dos_hdr_->e_magic != IMAGE_DOS_SIGNATURE)
        throw new std::exception("Wrong DOS signature.");

    nt_hdr32_ = reinterpret_cast<pe::ImageNtHeaders32*>(ptr_ + dos_hdr_->e_lfanew);
    nt_hdr64_ = reinterpret_cast<pe::ImageNtHeaders64*>(ptr_ + dos_hdr_->e_lfanew);

    if (nt_hdr32_->Signature != IMAGE_NT_SIGNATURE)
        throw new std::exception("Wrong NT signature.");

    if (nt_hdr32_->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
        x86_ = true;
    else if (nt_hdr32_->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
        x86_ = false;
    else
        throw new std::exception("Not a x86/amd64 PE.");
}

std::uint32_t peinjects::PeInjects::RvaToRaw(std::uint32_t rva)
{
    std::uint16_t number_of_sections = x86_ ? nt_hdr32_->FileHeader.NumberOfSections : nt_hdr64_->FileHeader.NumberOfSections;
    pe::ImageSectionHeader* first_section = reinterpret_cast<pe::ImageSectionHeader*>(ptr_ + dos_hdr_->e_lfanew + (x86_ ? sizeof(pe::ImageNtHeaders32) : sizeof(pe::ImageNtHeaders64)));

    for (int i = 0; i < number_of_sections; ++i) {
        if (first_section[i].VirtualAddress <= rva && rva < first_section[i].VirtualAddress + first_section[i].Misc.VirtualSize)
            return rva - first_section[i].VirtualAddress + first_section[i].PointerToRawData;
    }

    return -1;
}

std::uint32_t peinjects::PeInjects::RawToRva(std::uint32_t raw)
{
    std::uint16_t number_of_sections = x86_ ? nt_hdr32_->FileHeader.NumberOfSections : nt_hdr64_->FileHeader.NumberOfSections;
    pe::ImageSectionHeader* first_section = reinterpret_cast<pe::ImageSectionHeader*>(ptr_ + dos_hdr_->e_lfanew + (x86_ ? sizeof(pe::ImageNtHeaders32) : sizeof(pe::ImageNtHeaders64)));

    for (int i = 0; i < number_of_sections; ++i) {
        if (first_section[i].PointerToRawData <= raw && raw < first_section[i].PointerToRawData + first_section[i].SizeOfRawData)
            return raw - first_section[i].PointerToRawData + first_section[i].VirtualAddress;
    }

    return -1;
}
