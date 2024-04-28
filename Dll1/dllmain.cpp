#include "pch.h"
#include <windows.h>
#include <cstdint>
#include <vector>

#include <nlohmann/json.hpp>
#include "MinHook.h"
#include <string>


std::uintptr_t adhesive_base;

void* original_dump;

void __fastcall hk_dump(void* rcx, nlohmann::basic_json<>& a, const bool b, const bool c, const unsigned int d, const unsigned int e)
{
    // hwid gets changed here :)

    if (a.contains("i"))
    {
        auto identifiers = a.at("i");

        nlohmann::json new_list = { };

        const std::vector<std::string> substrings = { "MO_", "L2_", "L_", "F_", "U_", "MAC_", "BS1_", "SU1_", "SB_" };

        for (std::string identifier : identifiers)
        {
            for (const auto& substring : substrings) {
                size_t pos = identifier.find(substring);
                if (pos != std::string::npos) {
                    for (size_t i = pos + substring.length(); i < identifier.length(); ++i) {
                        if (std::isalpha(identifier[i])) {
                            identifier[i] = 'A' + std::rand() % 26;
                        }
                        else if (std::isdigit(identifier[i])) {
                            identifier[i] = '0' + std::rand() % 10;
                        }
                    }
                }
            }

            new_list.push_back(identifier);
            a.at("i") = new_list;
        }

    }

    if (a.contains("m"))
    {
        std::string m_identifier = a.at("m");
        for (size_t i = 0; i < m_identifier.length(); ++i) {
            if (std::isalpha(m_identifier[i])) {
                m_identifier[i] = 'a' + std::rand() % 26;
            }
            else if (std::isdigit(m_identifier[i])) {
                m_identifier[i] = '0' + std::rand() % 10;
            }
        }

        a.at("m") = m_identifier;
    }

    static_cast<void(*)(void*, const nlohmann::basic_json<>&, bool, bool, unsigned int, unsigned int)>(original_dump)(rcx, a, b, c, d, e);
}


std::vector<std::int16_t> pattern_to_byte(const std::string& pattern)
{
    std::vector<std::int16_t> bytes = { };

    const auto start = const_cast<char*>(&pattern[0]);
    const auto end = const_cast<char*>(&pattern[0]) + pattern.size();

    for (auto current = start; current < end; ++current) {
        if (*current == '?') {
            ++current;
            if (*current == '?')
                ++current;
            bytes.push_back(-1);
        }
        else {
            bytes.push_back(strtoul(current, &current, 16));
        }
    }

    return bytes;
}


std::uintptr_t find_pattern(std::uintptr_t mod_base, const std::string& pattern)
{
    const auto pattern_bytes = pattern_to_byte(pattern);

    const auto dos_headers = reinterpret_cast<IMAGE_DOS_HEADER*>(mod_base);
    const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<std::uint8_t*>(mod_base) + dos_headers->e_lfanew);

    const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;

    auto scan_bytes = reinterpret_cast<std::uint8_t*>(mod_base);

    for (auto i = 0ul; i < size_of_image - pattern_bytes.size(); ++i) {
        bool found = true;
        for (auto j = 0ul; j < pattern_bytes.size(); ++j) {
            if (scan_bytes[i + j] != pattern_bytes.data()[j] && pattern_bytes.data()[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return std::uintptr_t(reinterpret_cast<std::uintptr_t>(&scan_bytes[i]));
        }
    }

    return { };
}


void entry_point()
{
    adhesive_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("adhesive.dll"));

    while (!adhesive_base)
    {
        adhesive_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("adhesive.dll"));
    }

    // @pushfd if sig doesnt work : )

    const std::uintptr_t dump_addr = find_pattern(adhesive_base, "41 57 41 56 41 55 41 54 56 57 55 53 48 83 ec ? 44 0f 29 6c 24 30");

    MH_Initialize();

    MH_CreateHook((void*)dump_addr, hk_dump, &original_dump);
    MH_EnableHook(nullptr);

    while (1)
    {

    }
}

BOOL APIENTRY DllMain(void* module, unsigned long reason, void*)
{
    if (reason != DLL_PROCESS_ATTACH)
        return false;

    CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)entry_point, nullptr, 0, nullptr));

    return TRUE;
}
