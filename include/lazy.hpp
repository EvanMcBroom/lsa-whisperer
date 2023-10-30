// Copyright (C) 2022 Evan McBroom
#pragma once
#include <Windows.h>
#include <string>
#include <utility>

template<typename Function>
inline auto LazyLoad(HMODULE library, const std::string& procName) {
    return reinterpret_cast<Function*>(GetProcAddress(library, procName.data()));
}

template<typename Function>
inline std::pair<HMODULE, Function*> LazyLoad(const std::wstring& libraryName, const std::string& procName) {
    auto library{ LoadLibraryW(libraryName.data()) };
    return { library, (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr };
}

template<typename ReturnType, typename... ArgTypes>
inline auto LazyLoadWithType(const std::wstring& libraryName, const std::string& procName) {
    return LazyLoad<ReturnType (*)(ArgTypes...)>(libraryName, procName);
};

#define LAZY_LOAD_WSTRING(_) L#_

#define LAZY_LOAD_LIBRARY_AND_PROC(LIBRARY, PROC) \
    HMODULE Lazy##LIBRARY;                        \
    decltype(PROC)* Lazy##PROC;                   \
    std::tie(Lazy##LIBRARY, Lazy##PROC) = LazyLoad<decltype(PROC)>(LAZY_LOAD_WSTRING(LIBRARY##.dll), #PROC);

#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    auto Lazy##PROC{ (LIBRARY) ? LazyLoad<decltype(PROC)>(LIBRARY, #PROC) : nullptr };