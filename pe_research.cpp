#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>

#pragma comment(lib, "Advapi32.lib")

struct SectionInfo {
    std::string name;
    DWORD virtualAddress{};
    DWORD virtualSize{};
    DWORD rawAddress{};
    DWORD rawSize{};
    DWORD characteristics{};
    double entropy{};
};

struct Analysis {
    bool mz = false;
    bool pe = false;

    WORD machine = 0;
    WORD sections = 0;
    DWORD timestamp = 0;
    DWORD entryPoint = 0;
    ULONGLONG imageBase = 0;
    DWORD imageSize = 0;

    std::vector<SectionInfo> sectionInfo;
    std::set<std::string> warnings;

    std::string md5;
    std::string sha1;
    std::string sha256;
};

static std::string Hex(uint64_t value) {
    std::ostringstream out;
    out << "0x"
        << std::hex
        << std::uppercase
        << value;
    return out.str();
}

static double Entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0)
        return 0.0;

    uint64_t counts[256]{};

    for (size_t i = 0; i < size; ++i)
        counts[data[i]]++;

    double result = 0.0;

    for (uint64_t count : counts) {
        if (count == 0)
            continue;

        const double probability =
            static_cast<double>(count) /
            static_cast<double>(size);

        result -= probability * std::log2(probability);
    }

    return result;
}

static std::string HashFile(
    const std::vector<uint8_t>& data,
    ALG_ID algorithm
) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;

    if (!CryptAcquireContextA(
        &provider,
        nullptr,
        nullptr,
        PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT
    )) {
        return {};
    }

    if (!CryptCreateHash(
        provider,
        algorithm,
        0,
        0,
        &hash
    )) {
        CryptReleaseContext(provider, 0);
        return {};
    }

    if (!CryptHashData(
        hash,
        data.data(),
        static_cast<DWORD>(data.size()),
        0
    )) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    DWORD length = 0;
    DWORD lengthSize = sizeof(length);

    if (!CryptGetHashParam(
        hash,
        HP_HASHSIZE,
        reinterpret_cast<BYTE*>(&length),
        &lengthSize,
        0
    )) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    std::vector<BYTE> digest(length);

    if (!CryptGetHashParam(
        hash,
        HP_HASHVAL,
        digest.data(),
        &length,
        0
    )) {
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return {};
    }

    std::ostringstream result;

    for (BYTE byte : digest) {
        result << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);

    return result.str();
}

static bool RangeValid(
    size_t fileSize,
    uint64_t offset,
    uint64_t length
) {
    if (offset > fileSize)
        return false;

    return length <= fileSize - offset;
}

static std::string SectionName(
    const IMAGE_SECTION_HEADER& section
) {
    char name[9]{};

    std::memcpy(
        name,
        section.Name,
        IMAGE_SIZEOF_SHORT_NAME
    );

    return std::string(name);
}

static bool IsSuspiciousSectionName(
    const std::string& name
) {
    static const std::set<std::string> suspicious = {
        ".upx",
        "UPX0",
        "UPX1",
        "UPX2",
        ".aspack",
        ".adata",
        ".packed",
        ".vmp0",
        ".vmp1",
        ".themida"
    };

    return suspicious.contains(name);
}

static bool AnalyzePE(
    const std::vector<uint8_t>& data,
    Analysis& result
) {
    if (data.size() < sizeof(IMAGE_DOS_HEADER))
        return false;

    const auto* dos =
        reinterpret_cast<const IMAGE_DOS_HEADER*>(data.data());

    result.mz = dos->e_magic == IMAGE_DOS_SIGNATURE;

    if (!result.mz) {
        result.warnings.insert("Missing MZ DOS signature.");
        return false;
    }

    const uint32_t peOffset =
        static_cast<uint32_t>(dos->e_lfanew);

    if (!RangeValid(
        data.size(),
        peOffset,
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
    )) {
        result.warnings.insert(
            "Invalid or out-of-range PE header offset."
        );
        return false;
    }

    const DWORD* signature =
        reinterpret_cast<const DWORD*>(
            data.data() + peOffset
        );

    if (*signature != IMAGE_NT_SIGNATURE) {
        result.warnings.insert(
            "PE signature was not found."
        );
        return false;
    }

    result.pe = true;

    const auto* fileHeader =
        reinterpret_cast<const IMAGE_FILE_HEADER*>(
            data.data() +
            peOffset +
            sizeof(DWORD)
        );

    result.machine = fileHeader->Machine;
    result.sections = fileHeader->NumberOfSections;
    result.timestamp = fileHeader->TimeDateStamp;

    const size_t optionalOffset =
        peOffset +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER);

    if (!RangeValid(
        data.size(),
        optionalOffset,
        fileHeader->SizeOfOptionalHeader
    )) {
        result.warnings.insert(
            "Optional header exceeds file boundaries."
        );
        return false;
    }

    if (fileHeader->SizeOfOptionalHeader <
        sizeof(WORD)) {
        result.warnings.insert(
            "Optional header is too small."
        );
        return false;
    }

    const WORD magic =
        *reinterpret_cast<const WORD*>(
            data.data() + optionalOffset
        );

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {

        if (fileHeader->SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64)) {
            result.warnings.insert(
                "Truncated PE32+ optional header."
            );
            return false;
        }

        const auto* optional =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(
                data.data() + optionalOffset
            );

        result.entryPoint =
            optional->AddressOfEntryPoint;

        result.imageBase =
            optional->ImageBase;

        result.imageSize =
            optional->SizeOfImage;

    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {

        if (fileHeader->SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER32)) {
            result.warnings.insert(
                "Truncated PE32 optional header."
            );
            return false;
        }

        const auto* optional =
            reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
                data.data() + optionalOffset
            );

        result.entryPoint =
            optional->AddressOfEntryPoint;

        result.imageBase =
            optional->ImageBase;

        result.imageSize =
            optional->SizeOfImage;

    } else {
        result.warnings.insert(
            "Unknown optional-header magic."
        );
        return false;
    }

    const size_t sectionOffset =
        optionalOffset +
        fileHeader->SizeOfOptionalHeader;

    const uint64_t sectionTableSize =
        static_cast<uint64_t>(fileHeader->NumberOfSections) *
        sizeof(IMAGE_SECTION_HEADER);

    if (!RangeValid(
        data.size(),
        sectionOffset,
        sectionTableSize
    )) {
        result.warnings.insert(
            "Section table exceeds file boundaries."
        );
        return false;
    }

    const auto* sections =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            data.data() + sectionOffset
        );

    for (WORD i = 0;
         i < fileHeader->NumberOfSections;
         ++i) {

        const auto& section = sections[i];

        SectionInfo info;

        info.name = SectionName(section);
        info.virtualAddress =
            section.VirtualAddress;

        info.virtualSize =
            section.Misc.VirtualSize;

        info.rawAddress =
            section.PointerToRawData;

        info.rawSize =
            section.SizeOfRawData;

        info.characteristics =
            section.Characteristics;

        if (section.SizeOfRawData > 0 &&
            RangeValid(
                data.size(),
                section.PointerToRawData,
                section.SizeOfRawData
            )) {

            const auto* bytes =
                data.data() +
                section.PointerToRawData;

            info.entropy =
                Entropy(
                    bytes,
                    section.SizeOfRawData
                );

        } else if (section.SizeOfRawData != 0) {

            result.warnings.insert(
                "Section contains an invalid raw-data range: " +
                info.name
            );
        }

        if (info.entropy >= 7.2) {
            result.warnings.insert(
                "High entropy section: " +
                info.name
            );
        }

        if (IsSuspiciousSectionName(info.name)) {
            result.warnings.insert(
                "Known packer-like section name: " +
                info.name
            );
        }

        const bool executable =
            (info.characteristics &
             IMAGE_SCN_MEM_EXECUTE) != 0;

        const bool writable =
            (info.characteristics &
             IMAGE_SCN_MEM_WRITE) != 0;

        if (executable && writable) {
            result.warnings.insert(
                "Section is both executable and writable: " +
                info.name
            );
        }

        result.sectionInfo.push_back(info);
    }

    return true;
}

static void PrintReport(
    const Analysis& a,
    const std::string& path,
    size_t fileSize
) {
    std::cout
        << "\n========================================\n"
        << "       MALWARE RESEARCH - C++\n"
        << "       STATIC PE ANALYSIS\n"
        << "========================================\n\n";

    std::cout
        << "File        : " << path << '\n'
        << "Size        : " << fileSize << " bytes\n"
        << "MZ          : " << (a.mz ? "YES" : "NO") << '\n'
        << "PE          : " << (a.pe ? "YES" : "NO") << '\n';

    std::cout
        << "MD5         : " << a.md5 << '\n'
        << "SHA1        : " << a.sha1 << '\n'
        << "SHA256      : " << a.sha256 << "\n\n";

    if (!a.pe)
        return;

    std::cout
        << "[PE HEADER]\n"
        << "Machine     : " << Hex(a.machine) << '\n'
        << "Sections    : " << a.sections << '\n'
        << "Timestamp   : " << a.timestamp << '\n'
        << "Entry Point : " << Hex(a.entryPoint) << '\n'
        << "Image Base  : " << Hex(a.imageBase) << '\n'
        << "Image Size  : " << Hex(a.imageSize) << "\n\n";

    std::cout
        << "[SECTIONS]\n";

    for (const auto& section : a.sectionInfo) {
        std::cout
            << "  " << section.name << '\n'
            << "    RVA        : "
            << Hex(section.virtualAddress) << '\n'
            << "    Virtual    : "
            << section.virtualSize << '\n'
            << "    Raw size   : "
            << section.rawSize << '\n'
            << "    Raw offset : "
            << Hex(section.rawAddress) << '\n'
            << "    Entropy    : "
            << std::fixed
            << std::setprecision(4)
            << section.entropy
            << "\n\n";
    }

    std::cout << "[STATIC INDICATORS]\n";

    if (a.warnings.empty()) {
        std::cout
            << "  No heuristic indicators triggered.\n";
    } else {
        for (const auto& warning : a.warnings) {
            std::cout
                << "  [!] "
                << warning
                << '\n';
        }
    }

    std::cout
        << "\n[SAFETY]\n"
        << "  Sample executed : NO\n"
        << "  Sample loaded   : NO\n"
        << "  Network access  : NO\n"
        << "  Sample modified  : NO\n\n";
}

int main(int argc, char* argv[]) {

    if (argc != 2) {
        std::cerr
            << "Usage: pe_research.exe <sample.exe>\n";
        return 1;
    }

    const std::string path = argv[1];

    std::ifstream file(
        path,
        std::ios::binary
    );

    if (!file) {
        std::cerr
            << "[-] Cannot open file.\n";
        return 1;
    }

    file.seekg(
        0,
        std::ios::end
    );

    const std::streamsize size =
        file.tellg();

    if (size <= 0) {
        std::cerr
            << "[-] Empty or unreadable file.\n";
        return 1;
    }

    file.seekg(
        0,
        std::ios::beg
    );

    std::vector<uint8_t> data(
        static_cast<size_t>(size)
    );

    if (!file.read(
        reinterpret_cast<char*>(data.data()),
        size
    )) {
        std::cerr
            << "[-] Failed to read file.\n";
        return 1;
    }

    Analysis analysis;

    analysis.md5 =
        HashFile(data, CALG_MD5);

    analysis.sha1 =
        HashFile(data, CALG_SHA1);

    analysis.sha256 =
        HashFile(data, CALG_SHA_256);

    AnalyzePE(
        data,
        analysis
    );

    PrintReport(
        analysis,
        path,
        data.size()
    );

    return 0;
}
