#pragma once
#include <MsChapp.h>
#include <string>
#include <vector>

typedef struct _USER_SESSION_KEY {
    CYPHER_BLOCK data[2];
} USER_SESSION_KEY, * PUSER_SESSION_KEY;

std::vector<byte> CalculateNtOwfPassword(const std::string& password);
std::vector<byte> HashMessage(const std::wstring& algoType, const std::vector<byte>& message);
std::vector<byte> HexDecode(const std::wstring& asciiHex);