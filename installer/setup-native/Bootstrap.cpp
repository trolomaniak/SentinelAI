#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "NativePayload.h"

// No CLR runs in this executable. In particular, the elevated process never
// trusts .NET's user-configurable, file-existence-only single-file cache.
// Only kernel32 is imported: other Windows APIs are loaded from System32 after
// fixing the native DLL search policy, avoiding adjacent DLLs before wWinMain.
namespace
{
    constexpr std::uint64_t kMaximumExpandedBytes = 2ull * 1024 * 1024 * 1024;
    constexpr DWORD kMaximumFileBytes = 512u * 1024 * 1024;
    constexpr DWORD kHostWaitMilliseconds = 30u * 60 * 1000;
    constexpr wchar_t kHostName[] = L"SentinelAI.Setup.Host.exe";
    constexpr wchar_t kTemporaryDirectory[] = L"temp";
    constexpr GUID kProgramDataFolder =
        { 0x62ab5d82, 0xfdc1, 0x4dc3, { 0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97 } };

    static_assert(kSentinelAIPayloadFileCount > 0 && kSentinelAIPayloadFileCount <= 4096,
        "The native payload must contain 1..4096 files.");

    void Require(bool condition)
    {
        if (!condition) throw std::runtime_error("Setup bootstrap failed.");
    }

    class UniqueHandle
    {
    public:
        explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
        ~UniqueHandle() { Reset(); }
        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;
        UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.Release()) {}
        UniqueHandle& operator=(UniqueHandle&& other) noexcept
        {
            if (this != &other) { Reset(); handle_ = other.Release(); }
            return *this;
        }
        HANDLE Get() const noexcept { return handle_; }
        bool Valid() const noexcept { return handle_ && handle_ != INVALID_HANDLE_VALUE; }
        void Reset() noexcept
        {
            if (Valid()) CloseHandle(handle_);
            handle_ = nullptr;
        }
    private:
        HANDLE Release() noexcept { const HANDLE value = handle_; handle_ = nullptr; return value; }
        HANDLE handle_;
    };

    template<typename T> T Resolve(HMODULE module, const char* name)
    {
        const FARPROC address = GetProcAddress(module, name);
        Require(address != nullptr);
        T function{};
        static_assert(sizeof(function) == sizeof(address), "Windows function pointer size mismatch.");
        std::memcpy(&function, &address, sizeof(function));
        return function;
    }

    // Declare pointers using Windows' authoritative signatures, but never call
    // imported advapi32/bcrypt/shell32/ole32/user32 entry points directly.
    struct SystemApis
    {
        decltype(&::MessageBoxW) message_box{};
        decltype(&::ConvertStringSecurityDescriptorToSecurityDescriptorW) parse_descriptor{};
        decltype(&::ConvertStringSidToSidW) parse_sid{};
        decltype(&::CreateWellKnownSid) well_known_sid{};
        decltype(&::CheckTokenMembership) token_membership{};
        decltype(&::GetSecurityInfo) security_info{};
        decltype(&::GetSecurityDescriptorControl) descriptor_control{};
        decltype(&::GetAce) get_ace{};
        decltype(&::IsValidAcl) valid_acl{};
        decltype(&::IsValidSid) valid_sid{};
        decltype(&::EqualSid) equal_sid{};
        decltype(&::SHGetKnownFolderPath) known_folder{};
        decltype(&::CoTaskMemFree) task_free{};
        decltype(&::BCryptOpenAlgorithmProvider) open_algorithm{};
        decltype(&::BCryptCloseAlgorithmProvider) close_algorithm{};
        decltype(&::BCryptCreateHash) create_hash{};
        decltype(&::BCryptDestroyHash) destroy_hash{};
        decltype(&::BCryptHashData) hash_data{};
        decltype(&::BCryptFinishHash) finish_hash{};
        decltype(&::BCryptGenRandom) random_bytes{};

        ~SystemApis()
        {
            for (auto module = modules_.rbegin(); module != modules_.rend(); ++module) FreeLibrary(*module);
        }
        void Initialize()
        {
            Require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != FALSE);
            const HMODULE user = Load(L"user32.dll");
            message_box = Resolve<decltype(message_box)>(user, "MessageBoxW");
            const HMODULE security = Load(L"advapi32.dll");
            parse_descriptor = Resolve<decltype(parse_descriptor)>(security, "ConvertStringSecurityDescriptorToSecurityDescriptorW");
            parse_sid = Resolve<decltype(parse_sid)>(security, "ConvertStringSidToSidW");
            well_known_sid = Resolve<decltype(well_known_sid)>(security, "CreateWellKnownSid");
            token_membership = Resolve<decltype(token_membership)>(security, "CheckTokenMembership");
            security_info = Resolve<decltype(security_info)>(security, "GetSecurityInfo");
            descriptor_control = Resolve<decltype(descriptor_control)>(security, "GetSecurityDescriptorControl");
            get_ace = Resolve<decltype(get_ace)>(security, "GetAce");
            valid_acl = Resolve<decltype(valid_acl)>(security, "IsValidAcl");
            valid_sid = Resolve<decltype(valid_sid)>(security, "IsValidSid");
            equal_sid = Resolve<decltype(equal_sid)>(security, "EqualSid");
            known_folder = Resolve<decltype(known_folder)>(Load(L"shell32.dll"), "SHGetKnownFolderPath");
            task_free = Resolve<decltype(task_free)>(Load(L"ole32.dll"), "CoTaskMemFree");
            const HMODULE crypto = Load(L"bcrypt.dll");
            open_algorithm = Resolve<decltype(open_algorithm)>(crypto, "BCryptOpenAlgorithmProvider");
            close_algorithm = Resolve<decltype(close_algorithm)>(crypto, "BCryptCloseAlgorithmProvider");
            create_hash = Resolve<decltype(create_hash)>(crypto, "BCryptCreateHash");
            destroy_hash = Resolve<decltype(destroy_hash)>(crypto, "BCryptDestroyHash");
            hash_data = Resolve<decltype(hash_data)>(crypto, "BCryptHashData");
            finish_hash = Resolve<decltype(finish_hash)>(crypto, "BCryptFinishHash");
            random_bytes = Resolve<decltype(random_bytes)>(crypto, "BCryptGenRandom");
        }
    private:
        HMODULE Load(const wchar_t* name)
        {
            const HMODULE module = LoadLibraryExW(name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            Require(module != nullptr);
            try { modules_.push_back(module); }
            catch (...) { FreeLibrary(module); throw; }
            return module;
        }
        std::vector<HMODULE> modules_;
    };

    bool EqualOrdinal(const std::wstring& first, const std::wstring& second)
    {
        return CompareStringOrdinal(first.c_str(), static_cast<int>(first.size()),
            second.c_str(), static_cast<int>(second.size()), TRUE) == CSTR_EQUAL;
    }
    struct OrdinalInsensitive
    {
        bool operator()(const std::wstring& first, const std::wstring& second) const
        {
            const int comparison = CompareStringOrdinal(first.c_str(), static_cast<int>(first.size()),
                second.c_str(), static_cast<int>(second.size()), TRUE);
            Require(comparison != 0);
            return comparison == CSTR_LESS_THAN;
        }
    };

    class LocalAllocation
    {
    public:
        explicit LocalAllocation(void* memory = nullptr) noexcept : memory_(memory) {}
        ~LocalAllocation() { if (memory_) LocalFree(memory_); }
        LocalAllocation(const LocalAllocation&) = delete;
        LocalAllocation& operator=(const LocalAllocation&) = delete;
        void* Get() const noexcept { return memory_; }
    private:
        void* memory_;
    };

    class PrivateAcl
    {
    public:
        explicit PrivateAcl(const SystemApis& api, bool directory)
        {
            Require(api.parse_descriptor(directory
                ? L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
                : L"O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                SDDL_REVISION_1, &descriptor_, nullptr) != FALSE);
            attributes_.nLength = static_cast<DWORD>(sizeof(attributes_));
            attributes_.lpSecurityDescriptor = descriptor_;
            attributes_.bInheritHandle = FALSE;
        }
        ~PrivateAcl() { if (descriptor_) LocalFree(descriptor_); }
        PrivateAcl(const PrivateAcl&) = delete;
        PrivateAcl& operator=(const PrivateAcl&) = delete;
        SECURITY_ATTRIBUTES* Attributes() noexcept { return &attributes_; }
    private:
        PSECURITY_DESCRIPTOR descriptor_{};
        SECURITY_ATTRIBUTES attributes_{};
    };

    class TrustedAccounts
    {
    public:
        explicit TrustedAccounts(const SystemApis& api) : api_(api)
        {
            DWORD size = static_cast<DWORD>(sizeof(administrators_));
            Require(api_.well_known_sid(WinBuiltinAdministratorsSid, nullptr, administrators_, &size) != FALSE);
            size = static_cast<DWORD>(sizeof(system_));
            Require(api_.well_known_sid(WinLocalSystemSid, nullptr, system_, &size) != FALSE);
            Require(api_.parse_sid(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &installer_) != FALSE);
            BOOL elevated_member = FALSE;
            Require(api_.token_membership(nullptr, administrators_, &elevated_member) != FALSE && elevated_member != FALSE);
        }
        ~TrustedAccounts() { if (installer_) LocalFree(installer_); }
        TrustedAccounts(const TrustedAccounts&) = delete;
        TrustedAccounts& operator=(const TrustedAccounts&) = delete;
        bool Private(PSID sid) const
        {
            return sid && (api_.equal_sid(sid, const_cast<BYTE*>(administrators_)) != FALSE ||
                api_.equal_sid(sid, const_cast<BYTE*>(system_)) != FALSE);
        }
        bool Ancestor(PSID sid) const
        {
            return Private(sid) || (sid && api_.equal_sid(sid, installer_) != FALSE);
        }
    private:
        const SystemApis& api_;
        alignas(DWORD) BYTE administrators_[SECURITY_MAX_SID_SIZE]{};
        alignas(DWORD) BYTE system_[SECURITY_MAX_SID_SIZE]{};
        PSID installer_{};
    };

    DWORD ExpandedRights(DWORD mask)
    {
        if ((mask & GENERIC_ALL) != 0) mask |= FILE_ALL_ACCESS;
        if ((mask & GENERIC_WRITE) != 0) mask |= FILE_GENERIC_WRITE;
        return mask;
    }

    void ValidateAcl(const SystemApis& api, const TrustedAccounts& accounts, HANDLE handle,
        bool private_path, bool program_data_ancestor)
    {
        PSID owner{};
        PACL dacl{};
        PSECURITY_DESCRIPTOR descriptor{};
        const DWORD result = api.security_info(handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr, &descriptor);
        const LocalAllocation allocation(descriptor);
        Require(result == ERROR_SUCCESS && owner && dacl && api.valid_sid(owner) && api.valid_acl(dacl));
        Require(private_path ? accounts.Private(owner) : accounts.Ancestor(owner));
        SECURITY_DESCRIPTOR_CONTROL control{};
        DWORD revision{};
        Require(api.descriptor_control(descriptor, &control, &revision) != FALSE);
        if (private_path) Require((control & SE_DACL_PROTECTED) != 0);

        DWORD dangerous_rights = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES |
            DELETE | FILE_DELETE_CHILD | WRITE_DAC | WRITE_OWNER;
        // Standard local ancestors permit creating a new directory name. Only
        // the known ProgramData ancestor additionally permits ordinary Write;
        // neither exemption permits deleting or mutating our protected child.
        if (!private_path) dangerous_rights &= ~FILE_APPEND_DATA;
        if (program_data_ancestor) dangerous_rights &= ~(FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES);

        for (DWORD index = 0; index < dacl->AceCount; ++index)
        {
            void* memory{};
            Require(api.get_ace(dacl, index, &memory) != FALSE && memory != nullptr);
            const auto header = static_cast<const ACE_HEADER*>(memory);
            Require(header->AceType == ACCESS_ALLOWED_ACE_TYPE || header->AceType == ACCESS_DENIED_ACE_TYPE);
            Require(header->AceSize >= offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8);
            const auto ace = static_cast<const ACCESS_ALLOWED_ACE*>(memory);
            const auto sid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
            const auto sid_header = static_cast<const SID*>(sid);
            Require(8u + 4u * sid_header->SubAuthorityCount <= header->AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart));
            Require(api.valid_sid(sid) != FALSE);
            if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
            if (private_path)
            {
                // Private staging is not merely non-writable: no untrusted
                // identity receives even read access or inherited child rights.
                Require(accounts.Private(sid));
            }
            else if ((header->AceFlags & INHERIT_ONLY_ACE) == 0 &&
                (ExpandedRights(ace->Mask) & dangerous_rights) != 0)
            {
                Require(accounts.Ancestor(sid));
            }
        }
    }

    std::wstring NativePath(const std::wstring& path) { return L"\\\\?\\" + path; }

    UniqueHandle OpenDirectory(const std::wstring& path)
    {
        UniqueHandle handle(CreateFileW(NativePath(path).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        Require(handle.Valid());
        BY_HANDLE_FILE_INFORMATION information{};
        Require(GetFileInformationByHandle(handle.Get(), &information) != FALSE &&
            (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 &&
            (information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0);
        // Omitting FILE_SHARE_DELETE keeps every opened parent from being
        // renamed/replaced while descendants are created and the host is alive.
        return handle;
    }

    void ValidateComponent(const std::wstring& component)
    {
        Require(!component.empty() && component.size() <= 255 && component != L"." && component != L".." &&
            component.back() != L' ' && component.back() != L'.');
        for (const wchar_t character : component)
            Require(character >= 32 && character != 127 && std::wcschr(L"<>:\"/\\|?*", character) == nullptr);
        const std::wstring base = component.substr(0, component.find(L'.'));
        Require(!EqualOrdinal(base, L"CON") && !EqualOrdinal(base, L"PRN") && !EqualOrdinal(base, L"AUX") &&
            !EqualOrdinal(base, L"NUL") && !EqualOrdinal(base, L"CONIN$") && !EqualOrdinal(base, L"CONOUT$"));
        if (base.size() == 4 && (EqualOrdinal(base.substr(0, 3), L"COM") || EqualOrdinal(base.substr(0, 3), L"LPT")))
            Require(base[3] < L'0' || base[3] > L'9');
    }

    std::wstring GetProgramData(const SystemApis& api)
    {
        PWSTR folder{};
        const HRESULT result = api.known_folder(kProgramDataFolder, 0, nullptr, &folder);
        if (FAILED(result) || folder == nullptr)
        {
            if (folder) api.task_free(folder);
            Require(false);
        }
        std::wstring path;
        try { path = folder; }
        catch (...) { api.task_free(folder); throw; }
        api.task_free(folder);
        Require(path.size() >= 4 && path.size() <= 180 &&
            ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
            path[1] == L':' && path[2] == L'\\' && path.back() != L'\\');
        std::array<wchar_t, MAX_PATH> canonical{};
        const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(canonical.size()), canonical.data(), nullptr);
        Require(length > 0 && length < canonical.size() && EqualOrdinal(path, canonical.data()));
        std::size_t start = 3;
        while (start < path.size())
        {
            const std::size_t end = path.find(L'\\', start);
            ValidateComponent(path.substr(start, end == std::wstring::npos ? end : end - start));
            if (end == std::wstring::npos) break;
            start = end + 1;
        }
        const std::wstring volume = path.substr(0, 3);
        std::array<wchar_t, 32> format{};
        Require(GetDriveTypeW(volume.c_str()) == DRIVE_FIXED &&
            GetVolumeInformationW(volume.c_str(), nullptr, 0, nullptr, nullptr, nullptr,
                format.data(), static_cast<DWORD>(format.size())) != FALSE && EqualOrdinal(format.data(), L"NTFS"));
        return path;
    }

    class Sha256
    {
    public:
        explicit Sha256(const SystemApis& api) : api_(api)
        {
            Require(api_.open_algorithm(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0);
        }
        ~Sha256() { if (algorithm_) api_.close_algorithm(algorithm_, 0); }
        Sha256(const Sha256&) = delete;
        Sha256& operator=(const Sha256&) = delete;
        class Hash
        {
        public:
            Hash(const SystemApis& api, BCRYPT_ALG_HANDLE algorithm) : api_(api)
            {
                Require(api_.create_hash(algorithm, &hash_, nullptr, 0, nullptr, 0, 0) >= 0);
            }
            ~Hash() { if (hash_) api_.destroy_hash(hash_); }
            Hash(const Hash&) = delete;
            Hash& operator=(const Hash&) = delete;
            void Add(const BYTE* bytes, DWORD count)
            {
                if (count) Require(api_.hash_data(hash_, const_cast<BYTE*>(bytes), count, 0) >= 0);
            }
            void Verify(const unsigned char* expected)
            {
                std::array<BYTE, 32> digest{};
                Require(api_.finish_hash(hash_, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0);
                Require(std::memcmp(digest.data(), expected, digest.size()) == 0);
            }
        private:
            const SystemApis& api_;
            BCRYPT_HASH_HANDLE hash_{};
        };
        Hash Begin() const { return Hash(api_, algorithm_); }
    private:
        const SystemApis& api_;
        BCRYPT_ALG_HANDLE algorithm_{};
    };

    struct PayloadFile
    {
        const SentinelAIEmbeddedFile* metadata;
        std::wstring path;
        const BYTE* bytes;
    };

    std::vector<PayloadFile> ValidatePayload(const Sha256& sha256)
    {
        std::vector<PayloadFile> files;
        files.reserve(kSentinelAIPayloadFileCount);
        std::set<std::wstring, OrdinalInsensitive> paths;
        std::set<WORD> ids;
        std::uint64_t total = 0;
        bool host_found = false;
        const HMODULE module = GetModuleHandleW(nullptr);
        Require(module != nullptr);
        for (const auto& metadata : kSentinelAIPayloadFiles)
        {
            Require(metadata.relative_path != nullptr && metadata.resource_id >= 1000 && ids.insert(metadata.resource_id).second);
            std::wstring relative = metadata.relative_path;
            Require(!relative.empty() && relative.size() <= 240 && relative.front() != L'/' && relative.back() != L'/');
            std::size_t start = 0;
            while (start < relative.size())
            {
                const std::size_t end = relative.find(L'/', start);
                const std::wstring component = relative.substr(start, end == std::wstring::npos ? end : end - start);
                ValidateComponent(component);
                if (start == 0) Require(!EqualOrdinal(component, kTemporaryDirectory));
                if (end == std::wstring::npos) break;
                start = end + 1;
            }
            Require(paths.insert(relative).second && metadata.expected_length <= kMaximumFileBytes &&
                metadata.expected_length <= kMaximumExpandedBytes - total);
            total += metadata.expected_length;
            if (EqualOrdinal(relative, kHostName)) host_found = true;
            const HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(metadata.resource_id), RT_RCDATA);
            Require(resource != nullptr && SizeofResource(module, resource) == metadata.expected_length);
            const HGLOBAL loaded = LoadResource(module, resource);
            const BYTE* bytes = loaded ? static_cast<const BYTE*>(LockResource(loaded)) : nullptr;
            Require(metadata.expected_length == 0 || bytes != nullptr);
            auto digest = sha256.Begin();
            digest.Add(bytes, metadata.expected_length);
            digest.Verify(metadata.sha256);
            std::replace(relative.begin(), relative.end(), L'/', L'\\');
            files.push_back({ &metadata, std::move(relative), bytes });
        }
        Require(host_found);
        return files;
    }

    class PrivateStaging
    {
    public:
        PrivateStaging(const SystemApis& api, const TrustedAccounts& accounts)
            : api_(api), accounts_(accounts), directory_acl_(api, true), file_acl_(api, false)
        {
            const std::wstring program_data = GetProgramData(api_);
            // Validate and retain handles from the drive root downwards. A
            // trusted final ACL cannot make a replaceable ancestor trustworthy.
            std::wstring ancestor = program_data.substr(0, 3);
            ValidateAncestor(ancestor, false);
            std::size_t position = 3;
            while (position < program_data.size())
            {
                const std::size_t separator = program_data.find(L'\\', position);
                ancestor = program_data.substr(0, separator);
                ValidateAncestor(ancestor, EqualOrdinal(ancestor, program_data));
                if (separator == std::wstring::npos) break;
                position = separator + 1;
            }
            const std::wstring root = program_data + L"\\SentinelAI-SetupHost";
            if (!CreateDirectoryW(NativePath(root).c_str(), directory_acl_.Attributes()))
                Require(GetLastError() == ERROR_ALREADY_EXISTS);
            auto root_handle = OpenDirectory(root);
            ValidateAcl(api_, accounts_, root_handle.Get(), true, false);
            directories_.push_back(std::move(root_handle));
            std::array<BYTE, 16> random{};
            Require(api_.random_bytes(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0);
            constexpr wchar_t hex[] = L"0123456789abcdef";
            std::wstring id;
            id.reserve(32);
            for (const BYTE value : random) { id += hex[value >> 4]; id += hex[value & 15]; }
            path_ = root + L"\\" + id;
            // Never adopt a pre-existing session, including a random collision.
            CreatePrivateDirectory(path_);
            temporary_path_ = path_ + L"\\" + kTemporaryDirectory;
            CreatePrivateDirectory(temporary_path_);
            created_.insert(temporary_path_);
            Require((path_ + L"\\" + kHostName).size() < MAX_PATH);
        }
        const std::wstring& Path() const noexcept { return path_; }
        const std::wstring& TemporaryPath() const noexcept { return temporary_path_; }
        void Extract(const std::vector<PayloadFile>& files, const Sha256& sha256)
        {
            for (const auto& file : files)
            {
                std::size_t separator = file.path.find(L'\\');
                while (separator != std::wstring::npos)
                {
                    const std::wstring directory = path_ + L"\\" + file.path.substr(0, separator);
                    if (created_.insert(directory).second) CreatePrivateDirectory(directory);
                    separator = file.path.find(L'\\', separator + 1);
                }
                const std::wstring destination = NativePath(path_ + L"\\" + file.path);
                UniqueHandle output(CreateFileW(destination.c_str(), GENERIC_WRITE | READ_CONTROL, 0,
                    file_acl_.Attributes(), CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                Require(output.Valid());
                ValidateAcl(api_, accounts_, output.Get(), true, false);
                DWORD written = 0;
                while (written < file.metadata->expected_length)
                {
                    const DWORD chunk = (std::min)(file.metadata->expected_length - written, static_cast<DWORD>(1024u * 1024));
                    DWORD actual{};
                    Require(WriteFile(output.Get(), file.bytes + written, chunk, &actual, nullptr) != FALSE && actual == chunk);
                    written += actual;
                }
                Require(FlushFileBuffers(output.Get()) != FALSE);
                output.Reset();
                // Keep verified runtime files read-locked for the child's full
                // lifetime; a missing/changed file is never silently reused.
                UniqueHandle input(CreateFileW(destination.c_str(), GENERIC_READ | READ_CONTROL,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
                Require(input.Valid());
                BY_HANDLE_FILE_INFORMATION information{};
                Require(GetFileInformationByHandle(input.Get(), &information) != FALSE &&
                    (information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) == 0 &&
                    information.nNumberOfLinks == 1 && information.nFileSizeHigh == 0 &&
                    information.nFileSizeLow == file.metadata->expected_length);
                ValidateAcl(api_, accounts_, input.Get(), true, false);
                auto digest = sha256.Begin();
                std::array<BYTE, 64 * 1024> buffer{};
                DWORD read_total = 0;
                while (read_total < file.metadata->expected_length)
                {
                    DWORD read{};
                    const DWORD chunk = (std::min)(file.metadata->expected_length - read_total, static_cast<DWORD>(buffer.size()));
                    Require(ReadFile(input.Get(), buffer.data(), chunk, &read, nullptr) != FALSE && read == chunk);
                    digest.Add(buffer.data(), read);
                    read_total += read;
                }
                digest.Verify(file.metadata->sha256);
                files_.push_back(std::move(input));
            }
        }
    private:
        void ValidateAncestor(const std::wstring& path, bool program_data)
        {
            auto handle = OpenDirectory(path);
            ValidateAcl(api_, accounts_, handle.Get(), false, program_data);
            directories_.push_back(std::move(handle));
        }
        void CreatePrivateDirectory(const std::wstring& path)
        {
            Require(CreateDirectoryW(NativePath(path).c_str(), directory_acl_.Attributes()) != FALSE);
            auto handle = OpenDirectory(path);
            ValidateAcl(api_, accounts_, handle.Get(), true, false);
            directories_.push_back(std::move(handle));
        }
        const SystemApis& api_;
        const TrustedAccounts& accounts_;
        PrivateAcl directory_acl_;
        PrivateAcl file_acl_;
        std::wstring path_;
        std::wstring temporary_path_;
        std::set<std::wstring, OrdinalInsensitive> created_;
        std::vector<UniqueHandle> directories_;
        std::vector<UniqueHandle> files_;
    };

    bool PrefixAsciiInsensitive(const std::wstring& name, const wchar_t* prefix)
    {
        const std::size_t length = std::wcslen(prefix);
        if (name.size() < length) return false;
        for (std::size_t index = 0; index < length; ++index)
        {
            wchar_t character = name[index];
            if (character >= L'a' && character <= L'z') character = static_cast<wchar_t>(character - (L'a' - L'A'));
            if (character != prefix[index]) return false;
        }
        return true;
    }

    bool IsExecutionOverride(const std::wstring& name)
    {
        return PrefixAsciiInsensitive(name, L"DOTNET_") || PrefixAsciiInsensitive(name, L"CORECLR_") ||
            PrefixAsciiInsensitive(name, L"COR_") || PrefixAsciiInsensitive(name, L"COMPLUS_") ||
            PrefixAsciiInsensitive(name, L"APPDOMAIN_MANAGER") || PrefixAsciiInsensitive(name, L"__COMPAT_") ||
            EqualOrdinal(name, L"DEVPATH");
    }

    std::vector<wchar_t> ChildEnvironment(const std::wstring& temporary_path)
    {
        LPWCH block = GetEnvironmentStringsW();
        Require(block != nullptr);
        struct EnvironmentOwner
        {
            LPWCH value;
            ~EnvironmentOwner() { FreeEnvironmentStringsW(value); }
        } owner{ block };
        std::vector<std::wstring> entries;
        std::size_t characters = 0;
        for (const wchar_t* current = block; *current;)
        {
            const std::size_t length = std::wcslen(current);
            Require(length <= 32767 && characters + length + 1 <= 1024 * 1024);
            characters += length + 1;
            const std::wstring entry(current, length);
            const std::size_t separator = entry.find(L'=', entry.front() == L'=' ? 1 : 0);
            Require(separator != std::wstring::npos && separator > 0);
            const std::wstring name = entry.substr(0, separator);
            // Preserve security policy, proxy and credential variables verbatim.
            // Only execution injection and temp-location overrides are removed.
            if (!IsExecutionOverride(name) && !EqualOrdinal(name, L"TEMP") && !EqualOrdinal(name, L"TMP"))
                entries.push_back(entry);
            current += length + 1;
        }
        entries.push_back(L"TEMP=" + temporary_path);
        entries.push_back(L"TMP=" + temporary_path);
        std::stable_sort(entries.begin(), entries.end(), OrdinalInsensitive{});
        std::vector<wchar_t> environment;
        environment.reserve(characters + 2 * temporary_path.size() + 16);
        for (const auto& entry : entries)
        {
            environment.insert(environment.end(), entry.begin(), entry.end());
            environment.push_back(L'\0');
        }
        environment.push_back(L'\0');
        return environment;
    }

    DWORD RunHost(const PrivateStaging& staging)
    {
        const std::wstring executable = staging.Path() + L"\\" + kHostName;
        const std::wstring command = L"\"" + executable + L"\"";
        std::vector<wchar_t> command_line(command.begin(), command.end());
        command_line.push_back(L'\0');
        auto environment = ChildEnvironment(staging.TemporaryPath());
        STARTUPINFOW startup{};
        startup.cb = static_cast<DWORD>(sizeof(startup));
        PROCESS_INFORMATION process{};
        Require(CreateProcessW(executable.c_str(), command_line.data(), nullptr, nullptr, FALSE,
            CREATE_UNICODE_ENVIRONMENT, environment.data(), staging.Path().c_str(), &startup, &process) != FALSE);
        const UniqueHandle process_handle(process.hProcess);
        const UniqueHandle thread_handle(process.hThread);
        const DWORD result = WaitForSingleObject(process_handle.Get(), kHostWaitMilliseconds);
        // Staging is retained, including on cancellation/timeout. This wrapper
        // never deletes installed code, terminates protection services or kills
        // an in-progress host that may still be completing service operations.
        if (result == WAIT_TIMEOUT) return ERROR_TIMEOUT;
        Require(result == WAIT_OBJECT_0);
        DWORD exit_code{};
        Require(GetExitCodeProcess(process_handle.Get(), &exit_code) != FALSE);
        return exit_code;
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int)
{
    SystemApis api;
    const wchar_t* failure = L"SentinelAI Setup could not initialize its protected Windows bootstrap.";
    try
    {
        api.Initialize();
        Require(arguments == nullptr || *arguments == L'\0');
        const TrustedAccounts accounts(api);
        const Sha256 sha256(api);
        failure = L"SentinelAI Setup could not validate its embedded installation runtime.";
        const auto payload = ValidatePayload(sha256);
        failure = L"SentinelAI Setup could not prepare a protected installation workspace. Existing protection services have not been changed.";
        PrivateStaging staging(api, accounts);
        staging.Extract(payload, sha256);
        failure = L"SentinelAI Setup could not complete its installation window. Check whether an installation window is still running before trying again.";
        const DWORD exit_code = RunHost(staging);
        if (exit_code == ERROR_TIMEOUT && api.message_box)
            api.message_box(nullptr, L"SentinelAI Setup is still running. Wait for its installation window to finish before trying again.",
                L"SentinelAI Setup", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND);
        return static_cast<int>(exit_code);
    }
    catch (...)
    {
        if (api.message_box) api.message_box(nullptr, failure, L"SentinelAI Setup", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        return ERROR_INSTALL_FAILURE;
    }
}
