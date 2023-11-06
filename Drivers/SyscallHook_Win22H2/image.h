#pragma once

std::uintptr_t getImageSectionByName(const std::uintptr_t imageBase, const char* sectionName, size_t* sizeOut);