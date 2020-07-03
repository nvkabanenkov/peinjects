#ifndef PEINJECTS_PEINJECTS_H
#define PEINJECTS_PEINJECTS_H

#include <string>
#include "pe.h"

namespace peinjects {

    class PeInjects {
    public:
        explicit PeInjects(void* pointer_to_pe);

        std::uint32_t GetEntryPoint() const {
            return x86_ ? nt_hdr32_->OptionalHeader.AddressOfEntryPoint : nt_hdr64_->OptionalHeader.AddressOfEntryPoint;
        }

        void SetEntryPoint(std::uint32_t entry_point) {
            if (x86_)
                nt_hdr32_->OptionalHeader.AddressOfEntryPoint = entry_point;
            else
                nt_hdr64_->OptionalHeader.AddressOfEntryPoint = entry_point;
        }

        std::uint32_t RvaToRaw(std::uint32_t rva);
        std::uint32_t RawToRva(std::uint32_t raw);

        pe::ImageNtHeaders32* GetNtHeaders32() {
            return nt_hdr32_;
        }

        pe::ImageNtHeaders64* GetNtHeaders64() {
            return nt_hdr64_;
        }

        bool IsX86() const {
            return x86_;
        }

    private:
        char* ptr_;
        int x86_;

        pe::ImageDosHeader* dos_hdr_;
        pe::ImageNtHeaders32* nt_hdr32_;
        pe::ImageNtHeaders64* nt_hdr64_;
    };

} // namespace peinjects


#endif //PEINJECTS_PEINJECTS_H
