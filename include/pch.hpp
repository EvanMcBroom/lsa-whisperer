#pragma once
// clang-format off
#include <Windows.h>
#define _NTDEF_ // Required to include both NTSecAPI.h and Winternl.h
#include <Winternl.h>
#define SECURITY_WIN32 // Required to include security.h
#include <security.h>
#include <NTSecAPI.h>
#include <NTSecPKG.h>
// clang-format on