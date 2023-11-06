#pragma once

bool hookSystemCall(std::uintptr_t hookFunction, std::uintptr_t systemFunction);
bool UnhookSystemCall();