#include <crypt.hpp>

#define STATUS_SUCCESS 0

std::vector<byte> CalculateNtOwfPassword(const std::string& password) {
    std::vector<byte> data{ password.begin(), password.end() };
    return HashMessage(BCRYPT_MD4_ALGORITHM, data);
}

std::vector<byte> HashMessage(const std::wstring& algoType, const std::vector<BYTE>& message) {
    std::vector<BYTE> result;
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, algoType.data(), nullptr, 0) == STATUS_SUCCESS) {
        DWORD hashObjectSize{ 0 }, bytesCopied{ 0 };
        if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&hashObjectSize), sizeof(DWORD), &bytesCopied, 0) == STATUS_SUCCESS) {
            // Assume this succeeds
            auto hashObject{ reinterpret_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, hashObjectSize)) };
            DWORD hashSize{ 0 };
            if (BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PBYTE>(&hashSize), sizeof(DWORD), &bytesCopied, 0) == STATUS_SUCCESS) {
                // Assume this succeeds
                auto hash{ reinterpret_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, hashSize)) };
                ZeroMemory(hash, hashSize);
                BCRYPT_HASH_HANDLE hashHandle;
                if (BCryptCreateHash(algorithm, &hashHandle, hashObject, hashObjectSize, nullptr, 0, 0) == STATUS_SUCCESS) {
                    // Assume these succeed
                    auto dataToHash{ message };
                    if (
                        BCryptHashData(hashHandle, dataToHash.data(), dataToHash.size(), 0) == STATUS_SUCCESS &&
                        BCryptFinishHash(hashHandle, hash, hashSize, 0) == STATUS_SUCCESS
                        ) {
                        result.resize(hashSize);
                        std::memcpy(result.data(), hash, hashSize);
                    }

                    BCryptDestroyHash(hashHandle);
                }
                HeapFree(GetProcessHeap(), 0, hash);
            }
            HeapFree(GetProcessHeap(), 0, hashObject);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    return result;
}

std::vector<byte> HexDecode(std::ostream& out, const std::wstring& asciiHex) {
    DWORD byteLength{ 0 };
    if (CryptStringToBinaryW(asciiHex.data(), 0, CRYPT_STRING_HEX, nullptr, &byteLength, nullptr, nullptr)) {
        std::vector<byte> bytes(byteLength, 0);
        byteLength = bytes.size();
        if (CryptStringToBinaryW(asciiHex.data(), 0, CRYPT_STRING_HEX, bytes.data(), &byteLength, nullptr, nullptr)) {
            return bytes;
        }
    }
    return std::vector<byte>();
}