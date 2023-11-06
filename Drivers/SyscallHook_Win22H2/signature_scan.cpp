#include "pch.h"
#include "signature_scan.h"

std::uintptr_t scanPattern(std::uint8_t* base, const size_t size, char* pattern, char* mask)
{
    const auto patternSize = strlen(mask);

    for (size_t i = {}; i < size - patternSize; i++)
    {
        for (size_t j = {}; j < patternSize; j++)
        {
            if (mask[j] != '?' && *reinterpret_cast<std::uint8_t*>(base + i + j) != static_cast<std::uint8_t>(pattern[j]))
                break;

            if (j == patternSize - 1)
                return reinterpret_cast<std::uintptr_t>(base) + i;
        }
    }

    return {};
}