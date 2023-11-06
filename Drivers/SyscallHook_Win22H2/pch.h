#pragma once

#define DRIVER_TAG 'hook'

#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>

#include <ntdef.h>
#include <ntimage.h>
#include <cstdint>
#include <cstddef>
#include <ntddk.h>

#include "evntrace.h"

#pragma comment(lib,"ntoskrnl.exe")