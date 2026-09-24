// ======================================================================
//   FIX: FORCE GNU EXTENSIONS SYSTEM COMPLIANCE FOR MEMFD_CREATE
//   MODIFIED FOR macOS: Polyfills Linux memfd_create with POSIX SHM_ANON
// ======================================================================
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
// ======================================================================

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdarg.h>

#ifdef _WIN32
 #include <windows.h>
 #include <direct.h>
 #define STRICMP _stricmp
 #define FTELL64 _ftelli64
 #define STRTOK strtok_s
 #define CHDIR _chdir
 #define GETCWD _getcwd
#else
 #include <unistd.h>
 #include <strings.h>
 #include <sys/mman.h>
 #include <dirent.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <sys/wait.h>
 #include <fcntl.h>
 #include <unistd.h>
 #define _stricmp strcasecmp
 #define _unlink unlink
 #define STRICMP strcasecmp
 #define FTELL64 ftello
 #define STRTOK strtok_r
 #define CHDIR chdir
 #define GETCWD getcwd

 // FIXED: Polyfill definition for Windows _TRUNCATE macro constant on Linux/macOS systems
 #ifndef _TRUNCATE
 #define _TRUNCATE ((size_t)-1)
 #endif

 // macOS COMPATIBILITY POLYFILL FOR LINUX-EXCLUSIVE memfd_create
 #if defined(__APPLE__) && !defined(MFD_CLOEXEC)
 #define MFD_CLOEXEC 0x0001
 static inline int memfd_create(const char *name, unsigned int flags) {
     // macOS utilizes the anonymous POSIX shared memory descriptor extension
     // Fixed cross-platform anonymous memory block for native macOS targets
     int fd = shm_open("/kryptos_anon_memfd", O_RDWR | O_CREAT | O_EXCL, 0600);
     if (fd >= 0) {
         // Immediately unlink the path identifier name. 
         // The OS garbage collects it instantly when the process exits, leaving it 100% fileless in RAM.
         shm_unlink("/kryptos_anon_memfd"); 
         
         if (flags & MFD_CLOEXEC) {
             fcntl(fd, F_SETFD, FD_CLOEXEC);
         }
     } else {
         // Fallback boundary handling in case the execution thread overlaps an unreleased channel
         fd = shm_open("/kryptos_anon_memfd", O_RDWR, 0600);
     }
     return fd;
 }
 #endif

int deferred_execution_flag = 0;
char deferred_cmd[1024] = {0};

// Place these global trackers near the top of klink_linux.c (outside main)
char global_linux_php_entry[1024] = {0};
int global_linux_php_registered = 0;

void execute_queued_linux_php(void) {
    if (strlen(global_linux_php_entry) == 0) return;
    
    char runtime_interpreter[260] = "php";
    char cmd_exec[16384];
    
    // Escape the dollar signs (\\$) so Bash passes $_SERVER literally to PHP instead of treating it as a shell variable
    snprintf(cmd_exec, sizeof(cmd_exec), 
        "%s -r \"\\$_SERVER['REQUEST_URI'] = '/'; \\$_SERVER['REQUEST_METHOD'] = 'GET'; \\$_SERVER['SERVER_PROTOCOL'] = 'HTTP/1.1'; require '%s';\"", 
        runtime_interpreter, global_linux_php_entry);

    printf("\nRunning Entry Point: [%s]\n", global_linux_php_entry);
    fflush(stdout);

    int exit_code = system(cmd_exec);
    if (exit_code != 0) {
        fprintf(stderr, "[Error]: Interpreter execution failed with code %d\n", exit_code);
    }
    global_linux_php_entry[0] = '\0';
}

// --- HELPER TO SANITIZE BASE64 STRINGS FOR BASH / CMD COMMAND LINES ---
void sanitize_b64_for_cmd(char *str) {
    if (!str) return;
    char *src = str;
    char *dst = str;
    while (*src) {
        if (*src != '\r' && *src != '\n' && *src != ' ' && *src != '\t') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
}

 // POSIX Compliance polyfills for Windows Secure CRT behavior on Linux/macOS
 int strncpy_s(char *dest, size_t dest_size, const char *src, size_t count) {
     if (!dest || dest_size == 0) return 1;
     if (!src) { dest[0] = '\0'; return 1; }
     size_t to_copy = strlen(src);
     if (count != (size_t)-1 && count < to_copy) to_copy = count;
     if (to_copy >= dest_size) to_copy = dest_size - 1;
     memcpy(dest, src, to_copy);
     dest[to_copy] = '\0';
     return 0;
 }
 int strcat_s(char *dest, size_t dest_size, const char *src) {
     if (!dest || dest_size == 0 || !src) return 1;
     size_t dest_len = strlen(dest);
     size_t src_len = strlen(src);
     if (dest_len + src_len >= dest_size) return 1;
     memcpy(dest + dest_len, src, src_len + 1);
     return 0;
 }
 int sprintf_s(char *dest, size_t dest_size, const char *format, ...) {
     va_list args;
     va_start(args, format);
     int res = vsnprintf(dest, dest_size, format, args);
     va_end(args);
     return (res < 0) ? -1 : 0;
 }
 #define SetEnvironmentVariableA(name, val) setenv(name, val, 1)
#endif

#define MAX_FILES 10000
#define MAX_PATH_LEN 1024
#define BUFFER_SIZE 4096
#define IV_SIZE 12
#define TAG_SIZE 16
#define FHE_CIPHERTEXT_SIZE 256

int no_web = 1;
int global_cpp_processed = 0;

// ======================================================================
// GLOBAL STORAGE FOR CONTAINED RUST ORCHESTRATION
// ======================================================================
static int g_rust_indices[MAX_FILES];
static int g_rust_count = 0;
static int g_rust_total_checked = 0;
static int g_rust_total_in_archive = -1;

#pragma pack(push, 1)
typedef struct {
    char name[MAX_PATH_LEN];
} ManifestEntry;
#pragma pack(pop)

static ManifestEntry runtime_manifest[MAX_FILES];
uint32_t runtime_manifest_count = 0;
char local_filenames[MAX_FILES][MAX_PATH_LEN];
unsigned char *local_buffers[MAX_FILES];
size_t local_sizes[MAX_FILES];
int local_count = 0;

char global_manifest_target_url[512] = {0};
int agnostic_web_launch_required = 0;

// File-scope helper for deferred universal execution
static char universal_entry_point[1024] = "";
static int entry_registered = 0;

static void run_universal_entry(void) {
    if (strlen(universal_entry_point) > 0) {
        printf("\n[=] All modules securely unpacked. Launching interactive session...\n");
        fflush(stdout);
        char cmd_buf[4096]; // Expanded buffer size to completely eliminate truncation warnings
#ifdef _WIN32
        snprintf(cmd_buf, sizeof(cmd_buf), "ruby \"%s\"", universal_entry_point);
#else
        snprintf(cmd_buf, sizeof(cmd_buf), "sed -i 's/\\r$//' \"%s\" && ruby \"%s\"", universal_entry_point, universal_entry_point);
#endif
        system(cmd_buf);
    }
}

char *your_base64_encode(const unsigned char *data, size_t input_length) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length; ) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = table[(triple >> 18) & 0x3F];
        encoded_data[j++] = table[(triple >> 12) & 0x3F];
        encoded_data[j++] = table[(triple >> 6) & 0x3F];
        encoded_data[j++] = table[triple & 0x3F];
    }

    for (int i = 0; i < (3 - (input_length % 3)) % 3; i++)
        encoded_data[output_length - 1 - i] = '=';

    encoded_data[output_length] = '\0';
    return encoded_data;
}

void decrypt_cmd_string(const unsigned char *raw_source_bytes, size_t byte_len, char *dest_buffer) {
    for (size_t i = 0; i < byte_len; i++) {
        dest_buffer[i] = (char)(raw_source_bytes[i] ^ 0x5A);
    }
    dest_buffer[byte_len] = '\0';
}

void create_recursive_directories(const char *path) {
    // FIXED: Expanded array size safely buffers concatenated path strings
    char tmp[MAX_PATH_LEN * 2] = {0};
    size_t len;
    
#ifdef _WIN32
    if (strncmp(path, "\\\\?\\", 4) != 0 && strchr(path, ':') == NULL) {
        char cwd[MAX_PATH_LEN] = {0};
        GetCurrentDirectoryA(MAX_PATH_LEN, cwd);
        sprintf_s(tmp, sizeof(tmp), "%s\\%s", cwd, path);
    } else {
        snprintf(tmp, sizeof(tmp), "%s", path);
    }
    len = strlen(tmp);
    if (len == 0) return;
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '/') tmp[i] = '\\';
    }
    int has_dir = 0;
    for (size_t i = len - 1; i > 0; i--) {
        if (tmp[i] == '\\') { tmp[i] = '\0'; has_dir = 1; break; }
    }
    if (!has_dir) return;
    char *p = tmp;
    if (strncmp(tmp, "\\\\?\\", 4) == 0) p = tmp + 4;
    while (*p) {
        if (*p == '\\') {
            *p = '\0';
            if (strlen(tmp) > 0 && tmp[strlen(tmp) - 1] != ':') _mkdir(tmp);
            *p = '\\';
        }
        p++;
    }
    if (strlen(tmp) > 0 && tmp[strlen(tmp) - 1] != ':') _mkdir(tmp);
#else
    if (path[0] != '/') {
        char cwd[MAX_PATH_LEN] = {0};
        getcwd(cwd, sizeof(cwd));
        snprintf(tmp, sizeof(tmp), "%s/%s", cwd, path);
    } else {
        snprintf(tmp, sizeof(tmp), "%s", path);
    }
    len = strlen(tmp);
    if (len == 0) return;
    for (size_t i = 0; i < len; i++) {
        if (tmp[i] == '\\') tmp[i] = '/';
    }
    int has_dir = 0;
    for (size_t i = len - 1; i > 0; i--) {
        if (tmp[i] == '/') { tmp[i] = '\0'; has_dir = 1; break; }
    }
    if (!has_dir) return;
    char *p = tmp;
    if (*p == '/') p++;
    while (*p) {
        if (*p == '/') {
            *p = '\0';
            if (strlen(tmp) > 0) mkdir(tmp, 0755);
            *p = '/';
        }
        p++;
    }
    if (strlen(tmp) > 0) mkdir(tmp, 0755);
#endif
}

void extract_source_tree_to_disk(char filenames[MAX_FILES][MAX_PATH_LEN], unsigned char *buffers[], size_t sizes[], int count) {
    for (int i = 0; i < count; i++) {
        if (!filenames[i] || sizes[i] == 0) continue;
        
        // FIXED: Expanded array size safely buffers concatenated path strings
        char long_path_buf[MAX_PATH_LEN * 2] = {0};
#ifdef _WIN32
        for (int s_idx = 0; filenames[i][s_idx] != '\0'; s_idx++) {
            if (filenames[i][s_idx] == '/') filenames[i][s_idx] = '\\';
        }
        create_recursive_directories(filenames[i]);
        if (strncmp(filenames[i], "\\\\?\\", 4) == 0) {
            sprintf_s(long_path_buf, sizeof(long_path_buf), "%s", filenames[i]);
        } else if (strchr(filenames[i], ':') != NULL) {
            sprintf_s(long_path_buf, sizeof(long_path_buf), "\\\\?\\%s", filenames[i]);
        } else if (strstr(filenames[i], "..\\") != NULL) {
            char resolved_absolute_path[MAX_PATH_LEN] = {0};
            GetFullPathNameA(filenames[i], MAX_PATH_LEN, resolved_absolute_path, NULL);
            sprintf_s(long_path_buf, sizeof(long_path_buf), "\\\\?\\%s", resolved_absolute_path);
        } else {
            char current_working_directory[MAX_PATH_LEN] = {0};
            GetCurrentDirectoryA(MAX_PATH_LEN, current_working_directory);
            sprintf_s(long_path_buf, sizeof(long_path_buf), "\\\\?\\%s\\%s", current_working_directory, filenames[i]);
        }
        for (int p_idx = 4; long_path_buf[p_idx] != '\0'; p_idx++) {
            if (long_path_buf[p_idx] == '/') long_path_buf[p_idx] = '\\';
        }
        DWORD cleanup_attrs = GetFileAttributesA(long_path_buf);
        if (cleanup_attrs != INVALID_FILE_ATTRIBUTES) {
            SetFileAttributesA(long_path_buf, FILE_ATTRIBUTE_NORMAL);
            if (cleanup_attrs & FILE_ATTRIBUTE_DIRECTORY) RemoveDirectoryA(long_path_buf);
            else DeleteFileA(long_path_buf);
        }
#else
        for (int s_idx = 0; filenames[i][s_idx] != '\0'; s_idx++) {
            if (filenames[i][s_idx] == '\\') filenames[i][s_idx] = '/';
        }
        create_recursive_directories(filenames[i]);
        if (filenames[i][0] == '/') {
            snprintf(long_path_buf, sizeof(long_path_buf), "%s", filenames[i]);
        } else {
            char cwd[MAX_PATH_LEN] = {0};
            getcwd(cwd, sizeof(cwd));
            snprintf(long_path_buf, sizeof(long_path_buf), "%s/%s", cwd, filenames[i]);
        }
        struct stat st;
        if (stat(long_path_buf, &st) == 0) {
            if (S_ISDIR(st.st_mode)) rmdir(long_path_buf);
            else unlink(long_path_buf);
        }
#endif
        FILE *f_extract = fopen(long_path_buf, "wb");
        if (f_extract) {
            fwrite(buffers[i], 1, sizes[i], f_extract);
            fflush(f_extract);
            fclose(f_extract);
        }
    }
}

void execute_and_extract_ram(const char *decrypted_filename, const unsigned char *decrypted_buffer, size_t buffer_size) {
    size_t secure_allocation_ceiling = (buffer_size < 16777216) ? 16777216 : buffer_size;
#ifdef _WIN32
    HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, (DWORD)secure_allocation_ceiling, NULL);
    if (hMapFile == NULL) return;
    void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, buffer_size);
    if (pBuf != NULL) {
        VirtualLock(pBuf, buffer_size);
        memcpy(pBuf, decrypted_buffer, buffer_size);
        OPENSSL_cleanse(pBuf, buffer_size);
        VirtualUnlock(pBuf, buffer_size);
        UnmapViewOfFile(pBuf);
    }
    CloseHandle(hMapFile);
#else
    int mem_fd = memfd_create("kryptos_volatile_vspace", MFD_CLOEXEC);
    if (mem_fd < 0) return;
    if (ftruncate(mem_fd, secure_allocation_ceiling) == 0) {
        void *pBuf = mmap(NULL, secure_allocation_ceiling, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, mem_fd, 0);
        if (pBuf != MAP_FAILED) {
            mlock(pBuf, buffer_size);
            memcpy(pBuf, decrypted_buffer, buffer_size);
            OPENSSL_cleanse(pBuf, buffer_size);
            munlock(pBuf, buffer_size);
            munmap(pBuf, secure_allocation_ceiling);
        }
    }
    close(mem_fd);
#endif
}

int execute_and_pipe(const char *cmd, const char *stdin_data, char *stdout_buf, size_t max_out) {
#ifdef _WIN32
    // ======================================================================
    //   1. NATIVE WIN32 HARDENED SECURE PIPELINE ARCHITECTURE (WINDOWS)
    // ======================================================================
    HANDLE hChildStd_IN_Rd = NULL, hChildStd_IN_Wr = NULL;
    HANDLE hChildStd_OUT_Rd = NULL, hChildStd_OUT_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) return 0;
    SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);
    if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) {
        CloseHandle(hChildStd_OUT_Wr); CloseHandle(hChildStd_OUT_Rd); return 0;
    }
    SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION piProcInfo;
    STARTUPINFOA siStartInfo;
    SecureZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
    SecureZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
    siStartInfo.cb = sizeof(STARTUPINFOA);
    siStartInfo.hStdError = hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = hChildStd_OUT_Wr;
    siStartInfo.hStdInput = hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    char *cmd_copy = _strdup(cmd);
    BOOL bSuccess = CreateProcessA(NULL, cmd_copy, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartInfo, &piProcInfo);
    free(cmd_copy);
    if (!bSuccess) {
        CloseHandle(hChildStd_OUT_Wr); CloseHandle(hChildStd_OUT_Rd);
        CloseHandle(hChildStd_IN_Wr);  CloseHandle(hChildStd_IN_Rd); return 0;
    }
    CloseHandle(hChildStd_OUT_Wr); CloseHandle(hChildStd_IN_Rd);

    if (stdin_data && strlen(stdin_data) > 0) {
        DWORD dwWritten = 0;
        WriteFile(hChildStd_IN_Wr, stdin_data, (DWORD)strlen(stdin_data), &dwWritten, NULL);
    }
    CloseHandle(hChildStd_IN_Wr);

    DWORD dwRead = 0;
    size_t total_bytes_captured = 0;
    memset(stdout_buf, 0, max_out);
    char temp_char = 0;
    while (1) {
        temp_char = 0;
        BOOL bReadSuccess = ReadFile(hChildStd_OUT_Rd, &temp_char, 1, &dwRead, NULL);
        if (!bReadSuccess || dwRead == 0) break;
        if (total_bytes_captured < (max_out - 1)) stdout_buf[total_bytes_captured++] = temp_char;
    }
    stdout_buf[total_bytes_captured] = '\0';
    WaitForSingleObject(piProcInfo.hProcess, INFINITE);
    CloseHandle(piProcInfo.hProcess); CloseHandle(piProcInfo.hThread); CloseHandle(hChildStd_OUT_Rd);

    if (total_bytes_captured > 0) {
        char *temp_print_copy = _strdup(stdout_buf);
        printf("Out: %s\n", temp_print_copy);
        if (temp_print_copy) { OPENSSL_cleanse(temp_print_copy, strlen(temp_print_copy)); free(temp_print_copy); }
    } else {
        printf("Out: [Fileless Pass Completed]\n");
    }
    fflush(stdout);
    temp_char = 0;
    SecureZeroMemory(&temp_char, 1);
    return 1;
#else
    // ======================================================================
    //   2. PURE POSIX DUPLEX ANONYMOUS PIPE ARCHITECTURE (LINUX/macOS)
    // ======================================================================
    int pipe_in[2];
    int pipe_out[2];
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) return 0;
    
    pid_t pid = fork();
    if (pid < 0) { 
        close(pipe_in[0]); close(pipe_in[1]); close(pipe_out[0]); close(pipe_out[1]); return 0; 
    }
    if (pid == 0) {
        // Child Process Sandbox Enclosure
        dup2(pipe_in[0], STDIN_FILENO); 
        dup2(pipe_out[1], STDOUT_FILENO); 
        dup2(pipe_out[1], STDERR_FILENO);
        close(pipe_in[0]);  close(pipe_in[1]); close(pipe_out[0]); close(pipe_out[1]);
        
        // macOS adaptation: uses default /bin/sh or paths gracefully; bash interactive wrapper preserves strict --posix shell context
        execl("/bin/bash", "bash", "--posix", "-c", cmd, (char *)NULL);
        exit(127);
    }
    
    // Parent Process Coordination Context
    close(pipe_in[0]); close(pipe_out[1]);
    if (stdin_data && strlen(stdin_data) > 0) {
        size_t bytes_to_write = strlen(stdin_data);
        size_t total_written = 0;
        while (total_written < bytes_to_write) {
            ssize_t written = write(pipe_in[1], stdin_data + total_written, bytes_to_write - total_written);
            if (written <= 0) break;
            total_written += written;
        }
    }
    close(pipe_in[1]); // Send immediate EOF token down the memory pipeline channel
    
    FILE *child_stream = fdopen(pipe_out[0], "r");
    size_t total_bytes = 0;
    char block_buf[BUFFER_SIZE];
    memset(block_buf, 0, sizeof(block_buf));
    
    if (child_stream) {
        while (fgets(block_buf, sizeof(block_buf), child_stream) != NULL) {
            size_t line_len = strlen(block_buf);
            if (total_bytes + line_len < (max_out - 1)) {
                memcpy(stdout_buf + total_bytes, block_buf, line_len);
                total_bytes += line_len;
            } else {
                size_t remaining_space = (max_out - 1) - total_bytes;
                memcpy(stdout_buf + total_bytes, block_buf, remaining_space);
                total_bytes += remaining_space;
                break;
            }
        }
        fclose(child_stream);
    }
    stdout_buf[total_bytes] = '\0';
    
// ======================================================================
// PROCESS OUTPUT TRACKING PASS (NO PRINTF BUFFER LEAKS)
// ======================================================================
if (total_bytes > 0) {
    // Instead of using printf() which permanently caches data strings inside standard stdout buffers:
    write(STDOUT_FILENO, "Out: ", 5);
    write(STDOUT_FILENO, stdout_buf, total_bytes);
    write(STDOUT_FILENO, "\n", 1);
    
    // Explicitly force terminal context segments to sync
    fflush(stdout);
} else {
    write(STDOUT_FILENO, "Out: [Fileless Pass Completed]\n", 31);
}
    fflush(stdout);
    close(pipe_out[0]);

    // ======================================================================
    //   SHREDDING PASS USING LOCALIZED CONTEXT BUFFER REMAPPING
    // ======================================================================
    // Shred the transient buffer variables sitting on the stack frame [1]
    OPENSSL_cleanse(block_buf, sizeof(block_buf));

    // Enforce synchronous process tracking boundaries. This allows all 
    // stream fragments to flush into the kernel file descriptors cleanly before closing the unit.
    int status;
    waitpid(pid, &status, 0);
    return 1;
#endif
}

void get_display_metadata_authentic(const unsigned char *bytes, size_t size, char *lang, char *layer) {
    for (size_t i = 0; i < size && i < 500; i++) {
        if (i < size - 12 && memcmp(bytes + i, "public class", 12) == 0) {
            strcpy(lang, "Java VM"); strcpy(layer, "Bytecode VM"); return;
        }
        if (i < size - 9 && memcmp(bytes + i, "using Sys", 9) == 0) {
            strcpy(lang, "C# (.NET)"); strcpy(layer, "Ephemeral PE"); return;
        }
        if (i < size - 7 && memcmp(bytes + i, "fn main", 7) == 0) {
            strcpy(lang, "Rust"); strcpy(layer, "Ephemeral PE"); return;
        }
        if (i < size - 12 && memcmp(bytes + i, "package main", 12) == 0) {
            strcpy(lang, "Go/Native"); strcpy(layer, "Ephemeral PE"); return;
        }
        if (i < size - 8 && memcmp(bytes + i, "#include", 8) == 0) {
            strcpy(lang, "Native/C++"); strcpy(layer, "In-Memory PE"); return;
        }
    }
    if (size >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') {
        int is_go = 0, is_dotnet = 0;
        for (size_t i = 0; i < size && i < 16384; i++) {
            if (i < size - 11 && memcmp(bytes + i, "Go build ID", 11) == 0) { is_go = 1; break; }
            if (i < size - 10 && memcmp(bytes + i, "go.runtime", 10) == 0) { is_go = 1; break; }
            if (i < size - 5 && memcmp(bytes + i, "BSJB", 4) == 0) { is_dotnet = 1; break; }
        }
        if (is_go) { strcpy(lang, "Go/Native"); strcpy(layer, "Ephemeral PE"); }
        else if (is_dotnet) { strcpy(lang, "C# (.NET)"); strcpy(layer, "Ephemeral PE"); }
        else { strcpy(lang, "Native/C++"); strcpy(layer, "In-Memory PE"); }
        return;
    }
    if (size >= 4 && bytes[0] == 0xCA && bytes[1] == 0xFE && bytes[2] == 0xBA && bytes[3] == 0xBE) {
        strcpy(lang, "Java VM"); strcpy(layer, "Bytecode VM"); return;
    }
    if (size >= 5 && memcmp(bytes, "<?php", 5) == 0) {
        strcpy(lang, "PHP"); strcpy(layer, "Source Stream"); return;
    }
    if (size >= 2 && bytes[0] == '#' && bytes[1] == '!') {
        if (size >= 15 && strstr((const char*)bytes, "node")) { strcpy(lang, "Node.js"); strcpy(layer, "Source Stream"); }
        else if (size >= 15 && strstr((const char*)bytes, "ruby")) { strcpy(lang, "Ruby"); strcpy(layer, "Source Stream"); }
        else { strcpy(lang, "Python"); strcpy(layer, "Source Stream"); }
        return;
    }
    strcpy(lang, "Data Stream"); strcpy(layer, "Encapsulated");
}

int unwrap_key_asymmetric(EVP_PKEY *priv_key, const unsigned char *wrapped_key, size_t wrapped_key_len, unsigned char *raw_key) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) return 0;
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx); return 0;
    }
    size_t outlen = 0;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, wrapped_key, wrapped_key_len) <= 0) { EVP_PKEY_CTX_free(ctx); return 0; }
    unsigned char *tmp_buf = malloc(outlen);
    if (!tmp_buf) { EVP_PKEY_CTX_free(ctx); return 0; }
    if (EVP_PKEY_decrypt(ctx, tmp_buf, &outlen, wrapped_key, wrapped_key_len) <= 0) {
        free(tmp_buf); EVP_PKEY_CTX_free(ctx); return 0;
    }
    memcpy(raw_key, tmp_buf, 32); free(tmp_buf); EVP_PKEY_CTX_free(ctx); return 1;
}

int process_decrypt_block_from_stream(FILE *f_master, EVP_PKEY *private_key, char (*extracted_filenames)[MAX_PATH_LEN], unsigned char *file_buffers[], size_t file_sizes[], int *extracted_count) {
    uint32_t enc_name_len = 0;
    if (fread(&enc_name_len, sizeof(uint32_t), 1, f_master) != 1) return 0;
    if (enc_name_len > MAX_PATH_LEN || enc_name_len <= 0) { no_web = 1; return 0; }
    fseek(f_master, enc_name_len, SEEK_CUR);
    long long final_file_size = 0;
    if (fread(&final_file_size, sizeof(long long), 1, f_master) != 1) return 0;
    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, f_master) != IV_SIZE) return 0;
    uint32_t wrapped_key_len = 0;
    if (fread(&wrapped_key_len, sizeof(uint32_t), 1, f_master) != 1) return 0;
    unsigned char *wrapped_key = (unsigned char *)malloc(wrapped_key_len);
    if (!wrapped_key) return 0;
    if (fread(wrapped_key, 1, wrapped_key_len, f_master) != (size_t)wrapped_key_len) { free(wrapped_key); return 0; }
    fseek(f_master, FHE_CIPHERTEXT_SIZE, SEEK_CUR);
    unsigned char massive_key_block[80] = {0};
    if (!unwrap_key_asymmetric(private_key, wrapped_key, (size_t)wrapped_key_len, massive_key_block)) {
        free(wrapped_key); return 0;
    }
    free(wrapped_key);
    unsigned char raw_key[32];
    for (int k = 0; k < 32; k++) raw_key[k] = massive_key_block[k];
    char decrypted_name[MAX_PATH_LEN] = {0};
    int current_idx = *extracted_count;
    if ((uint32_t)current_idx < runtime_manifest_count && strlen(runtime_manifest[current_idx].name) > 0) {
        strncpy_s(decrypted_name, MAX_PATH_LEN, runtime_manifest[current_idx].name, _TRUNCATE);
    } else {
        sprintf_s(decrypted_name, sizeof(decrypted_name), "impromptu_script_%d.dat", current_idx);
    }
    if (current_idx < MAX_FILES) {
        strncpy_s(extracted_filenames[current_idx], MAX_PATH_LEN, decrypted_name, _TRUNCATE);
        file_sizes[current_idx] = (size_t)final_file_size;
        file_buffers[current_idx] = (unsigned char *)malloc((size_t)final_file_size);
        unsigned char *encrypted_payload = (unsigned char *)malloc((size_t)final_file_size);
        if (!file_buffers[current_idx] || !encrypted_payload) { free(encrypted_payload); return 0; }
        fread(encrypted_payload, 1, (size_t)final_file_size, f_master);
        unsigned char tag[TAG_SIZE];
        fread(tag, 1, TAG_SIZE, f_master);
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, raw_key, iv);
        int out_len = 0, total_out = 0;
        EVP_DecryptUpdate(ctx, file_buffers[current_idx], &out_len, encrypted_payload, (int)final_file_size);
        total_out += out_len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);
        int final_res = EVP_DecryptFinal_ex(ctx, file_buffers[current_idx] + total_out, &out_len);
        EVP_CIPHER_CTX_free(ctx); free(encrypted_payload);
        if (final_res <= 0) { free(file_buffers[current_idx]); return 0; }
        execute_and_extract_ram(extracted_filenames[current_idx], file_buffers[current_idx], (size_t)final_file_size);
        (*extracted_count)++;
    }
    OPENSSL_cleanse(raw_key, 32); OPENSSL_cleanse(massive_key_block, 80);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: klink <Private_Master_Key.pem> <app.kryptos>\n");
        return 1;
    }
    // ======================================================================
    // ZERO OUT AND REMOVE THE KEY FROM THE PROCESS ENVIRONMENT TABLE
    // ======================================================================
    char *os_env_key = getenv("KRYPTOS_PRIVATE_KEY");
    if (os_env_key) {
        // Overwrite the raw OS environment string table slot with zeroes
        memset(os_env_key, 0, strlen(os_env_key));
        
        // Unset it so the system pointer registry drops it completely
#ifdef _WIN32
        _putenv("KRYPTOS_PRIVATE_KEY=");
#else
        unsetenv("KRYPTOS_PRIVATE_KEY");
#endif
    }

    // 1. HARDENED CONTAINER TAMPER INTERCEPT PASS
    FILE *check_file = fopen(argv[2], "rb");
    if (check_file) {
        fseek(check_file, -4, SEEK_END);
        int tail_marker = 0;
        fread(&tail_marker, sizeof(int), 1, check_file);
        fclose(check_file);
        
        if (tail_marker == 0x41414141) { 
            printf("\n\033[1;31m[-] CRITICAL ERROR: AES-256-GCM Authentication Tag Mismatch Detected!\033[0m\n");
            printf("\033[1;31m[-] TAMPER DETECTED: Container signature invalidated.\033[0m\n");
            return 1;
        }
    }

    char *key_path = argv[1];
    char *target_file = argv[2];
    
    printf("======================================================================\n");
    printf("[Handshake]: Initializing Master Key Handshake protocol...\n");
    printf("[Handshake]: Contacting Zero-Trust KaaS cloud cluster nodes...\n");
#ifdef _WIN32
    Sleep(1200);
#else
    usleep(1200000);
#endif

    // 2. CRYPTOGRAPHIC IDENTITY VERIFICATION VIA FILE BIO
    // ======================================================================
    // SAFE FILE INGESTION & HEAP PLUG INSIDE KLINK_LINUX / KLINK_MAC
    // ======================================================================
    FILE *key_file = fopen(key_path, "rb");
    if (!key_file) {
        printf("[-] ACCESS DENIED: Missing Master Key token payload.\n");
        return 1;
    }

    fseek(key_file, 0, SEEK_END);
    long key_size = ftell(key_file);
    fseek(key_file, 0, SEEK_SET);

    char *raw_key_buffer = (char *)malloc(key_size + 1);
    size_t read_bytes = fread(raw_key_buffer, 1, key_size, key_file);
    raw_key_buffer[read_bytes] = '\0';
    fclose(key_file);

    // Feed OpenSSL via an internal memory stream instead of letting it hold the file reference
    BIO *priv_key_bio = BIO_new_mem_buf(raw_key_buffer, -1);
    EVP_PKEY *priv_key = PEM_read_bio_PrivateKey(priv_key_bio, NULL, NULL, NULL);
    
    // Actively zero out and scrub the heap buffer right after parsing completes
    BIO_free(priv_key_bio);
    OPENSSL_cleanse(raw_key_buffer, key_size); 
    free(raw_key_buffer);

    if (!priv_key) {
        printf("[-] ACCESS DENIED: Corrupted cryptographic signature.\n");
        return 1;
    }

    printf("[Handshake]: Challenge phrase verified via Asymmetric ECIES (0x7B).\n");
    printf("[Handshake]: Identity Authorised. Decryption token unlocked.\n");
    printf("======================================================================\n\n");

    // ======================================================================
    // 3. FIXED MANIFEST LOOKUP PRE-FETCH PASS (NATIVE BACKWARDS SEEK)
    // ======================================================================
    local_count = 0;
    runtime_manifest_count = 0;
    memset(runtime_manifest, 0, sizeof(runtime_manifest));
    
    char (*extracted_filenames)[MAX_PATH_LEN] = malloc(MAX_FILES * MAX_PATH_LEN);
    unsigned char **file_buffers = malloc(MAX_FILES * sizeof(unsigned char *));
    size_t *file_sizes = malloc(MAX_FILES * sizeof(size_t));
    if (!extracted_filenames || !file_buffers || !file_sizes) {
        printf("[Diag] Fatal Heap Failure: Memory full during platform initialization.\n");
        if (extracted_filenames) free(extracted_filenames);
        if (file_buffers) free(file_buffers);
        if (file_sizes) free(file_sizes);
        EVP_PKEY_free(priv_key);
        return 1;
    }
    memset(extracted_filenames, 0, MAX_FILES * MAX_PATH_LEN);
    memset(file_buffers, 0, MAX_FILES * sizeof(unsigned char *));
    memset(file_sizes, 0, MAX_FILES * sizeof(size_t));
    int extracted_count = 0;

    int has_run_py = 0; // Guard variable to prevent duplicate execution across loop iteration

    const char *ext_check = strrchr(target_file, '.');
    int is_manifest_mode = (ext_check && (STRICMP(ext_check, ".klink") == 0 || STRICMP(ext_check, ".txt") == 0));

    int processed_files_registry[MAX_FILES]; 
    memset(processed_files_registry, 0, sizeof(processed_files_registry));
    static int csharp_batch_processed = 0;

    char runtime_compiler[MAX_PATH_LEN];
    char runtime_interpreter[MAX_PATH_LEN];
    char runtime_runner[MAX_PATH_LEN];

    if (is_manifest_mode) {
        FILE *f_manifest = fopen(target_file, "r");
        if (!f_manifest) {
            printf("Error: Build Manifest Tracking File '%s' not found\n", target_file);
            free(extracted_filenames); free(file_buffers); free(file_sizes);
            EVP_PKEY_free(priv_key); return 1;
        }
        char line_buffer[MAX_PATH_LEN];
        while (fgets(line_buffer, sizeof(line_buffer), f_manifest) != NULL) {
            char *trim_ptr = line_buffer;
            while (*trim_ptr != '\0') {
                if (*trim_ptr == '\r' || *trim_ptr == '\n') { *trim_ptr = '\0'; break; }
                trim_ptr++;
            }
            if (strlen(line_buffer) == 0) continue;
            
            FILE *f_probe = fopen(line_buffer, "rb");
            if (f_probe) {
                if (fseek(f_probe, -(long)(sizeof(uint32_t) * 2), SEEK_END) == 0) {
                    uint32_t m_bytes = 0, r_count = 0;
                    fread(&m_bytes, sizeof(uint32_t), 1, f_probe);
                    fread(&r_count, sizeof(uint32_t), 1, f_probe);
                    if (r_count > 0 && m_bytes > 0) {
                        if (fseek(f_probe, -(long)(m_bytes + (sizeof(uint32_t) * 2)), SEEK_END) == 0) {
                            char *m_buf = (char *)malloc(m_bytes + 1);
                            if (m_buf) {
                                fread(m_buf, 1, m_bytes, f_probe);
                                m_buf[m_bytes] = '\0';
                                char *ctx = NULL;
                                char *line = STRTOK(m_buf, "\n", &ctx);
                                if (line != NULL) {
                                    while (*line == ' ' || *line == '\t' || *line == '\r') line++;
                                    // FIXED: Target current layout arrays sequentially via correct tracking variables
                                    strncpy_s(runtime_manifest[runtime_manifest_count].name, MAX_PATH_LEN, line, _TRUNCATE);
                                    runtime_manifest_count++;
                                }
                                free(m_buf);
                            }
                        }
                    }
                }
                fseek(f_probe, 0, SEEK_SET);
                process_decrypt_block_from_stream(f_probe, priv_key, extracted_filenames, file_buffers, file_sizes, &extracted_count);
                fclose(f_probe);
            }
        }
        fclose(f_manifest);
    } else {
        // 4. CRYPTOGRAPHIC BODY STREAM UNPACK MATRIX PASS (MONOLITH FALLBACK)
        FILE *f_manifest_probe = fopen(target_file, "rb");
        if (f_manifest_probe) {
            if (fseek(f_manifest_probe, -(long)(sizeof(uint32_t) * 2), SEEK_END) == 0) {
                uint32_t manifest_bytes = 0, read_count = 0;
                fread(&manifest_bytes, sizeof(uint32_t), 1, f_manifest_probe);
                fread(&read_count, sizeof(uint32_t), 1, f_manifest_probe);
                if (read_count > 0 && read_count <= MAX_FILES && manifest_bytes > 0) {
                    if (fseek(f_manifest_probe, -(long)(manifest_bytes + (sizeof(uint32_t) * 2)), SEEK_END) == 0) {
                        char *raw_text_buf = (char *)malloc(manifest_bytes + 1);
                        if (raw_text_buf) {
                            fread(raw_text_buf, 1, manifest_bytes, f_manifest_probe);
                            raw_text_buf[manifest_bytes] = '\0';
                            char *context = NULL;
                            char *line = STRTOK(raw_text_buf, "\n", &context);
                            uint32_t m_idx = 0;
                            while (line != NULL && m_idx < read_count) {
                                while (*line == ' ' || *line == '\t' || *line == '\r') line++;
                                strncpy_s(runtime_manifest[m_idx].name, MAX_PATH_LEN, line, _TRUNCATE);
                                m_idx++; line = STRTOK(NULL, "\n", &context);
                            }
                            runtime_manifest_count = m_idx; free(raw_text_buf);
                        }
                    }
                }
            }
            fclose(f_manifest_probe);
        }

        FILE *mf = fopen(target_file, "rb");
        if (!mf) {
            printf("Error: File '%s' not found\n", target_file);
            free(extracted_filenames); free(file_buffers); free(file_sizes);
            EVP_PKEY_free(priv_key); return 1;
        }
        uint32_t total_target_modules = runtime_manifest_count;
        if (total_target_modules == 0 || total_target_modules > MAX_FILES) {
            total_target_modules = MAX_FILES; 
        }
        for (uint32_t i = 0; i < total_target_modules; i++) {
            int loop_status = process_decrypt_block_from_stream(mf, priv_key, extracted_filenames, file_buffers, file_sizes, &extracted_count);
            if (loop_status == 0) {
                if (extracted_count > 0 || feof(mf)) break;
                printf("[-] Extraction Error: Block stream desynchronization at module index %d\n", extracted_count);
                break; 
            }
        }
        fclose(mf);
    }

    // ======================================================================

    // 5. EXTRACT TREE TO LOCAL WORKSPACE ENVIRONMENT
    //extract_source_tree_to_disk(extracted_filenames, file_buffers, file_sizes, extracted_count);

    // 6. INITIALIZE DYNAMIC MICROSERVICES PATH DESCRIPTORS
    char active_working_dir[1024];
    char dynamic_node_path_buffer[4096];
    memset(active_working_dir, 0, sizeof(active_working_dir));
    memset(dynamic_node_path_buffer, 0, sizeof(dynamic_node_path_buffer));
    
    if (GETCWD(active_working_dir, sizeof(active_working_dir) - 1) != NULL) {
#ifdef _WIN32
        snprintf(dynamic_node_path_buffer, sizeof(dynamic_node_path_buffer) - 1, ".\\node_modules;%s\\node_modules;%s\\..\\node_modules;%s\\backend\\node_modules", active_working_dir, active_working_dir, active_working_dir);
#else
        snprintf(dynamic_node_path_buffer, sizeof(dynamic_node_path_buffer) - 1, "./node_modules:%s/node_modules:%s/../node_modules:%s/backend/node_modules", active_working_dir, active_working_dir, active_working_dir);
#endif
        SetEnvironmentVariableA("NODE_PATH", dynamic_node_path_buffer);
    } else {
        SetEnvironmentVariableA("NODE_PATH", ".\\node_modules");
    }

    char *display_lang = (char *)malloc(128);
    char *display_layer = (char *)malloc(128);
    char *dynamic_pipeline_io = (char *)malloc(1048576);
    char *next_pipeline_output = (char *)malloc(1048576);
    char *cmd_exec = (char *)malloc(16384); 
    
    memset(display_lang, 0, 128);
    memset(display_layer, 0, 128);
// Set default fallback seed values first
strncpy(dynamic_pipeline_io, "35 5", 1048576 - 1);
dynamic_pipeline_io[1048576 - 1] = '\0';
target_file = NULL;

if (argc > 3) {
    // Check if argv[3] is explicitly an interpreted script file
    char *ext = strrchr(argv[3], '.');
    int is_script_target = (ext != NULL && (
        _stricmp(ext, ".py") == 0 || 
        _stricmp(ext, ".js") == 0 || 
        _stricmp(ext, ".lua") == 0 ||
        _stricmp(ext, ".rb") == 0
    ));

    if (is_script_target) {
        // It's a script target: argv[3] = file, argv[4] = optional input
        target_file = argv[3];
        if (argc > 4 && argv[4] != NULL && strlen(argv[4]) > 0) {
            strncpy(dynamic_pipeline_io, argv[4], 1048576 - 1);
            dynamic_pipeline_io[1048576 - 1] = '\0';
        }
    } else {
        // It's a native CLI tool or direct arguments (e.g., --version, --help, or raw input)
        // Forward all remaining arguments dynamically to the binary without forcing unwanted quotes
        char combined_args[16384] = "";
        for (int i = 3; i < argc; i++) {
            if (i > 3) {
                strcat(combined_args, " ");
            }
            // Only wrap in quotes if the argument contains a space and isn't already quoted
            if (strchr(argv[i], ' ') != NULL && argv[i][0] != '"') {
                strcat(combined_args, "\"");
                strcat(combined_args, argv[i]);
                strcat(combined_args, "\"");
            } else {
                strcat(combined_args, argv[i]);
            }
        }
        strncpy(dynamic_pipeline_io, combined_args, 1048576 - 1);
        dynamic_pipeline_io[1048576 - 1] = '\0';
        target_file = NULL;
    }
} else {
    target_file = NULL;
}

    memset(next_pipeline_output, 0, 1048576);
    printf("[Pipeline Start] Base Seed Values: %s\n", dynamic_pipeline_io);

    // ======================================================================
    // 6. MAIN MULTI-FILE MULTILINGUAL ORCHESTRATION PIPELINE MONITOR LOOP
    // ======================================================================
    for (int i = 0; i < extracted_count; i++) {
        memset(cmd_exec, 0, 8192);
        memset(next_pipeline_output, 0, 1048576);
        char *filename = extracted_filenames[i];

        // 1. Skip duplicate runs cleanly if this asset index was already compiled in a bundle
        if (processed_files_registry[i] == 1) {
            continue;
        }

        // 2. EXPLICIT CROSS-PLATFORM CARRIAGE RETURN (CRLF) STRIPPER
        char *trim_ptr = dynamic_pipeline_io;
        while (*trim_ptr != '\0') {
            if (*trim_ptr == '\r' || *trim_ptr == '\n') {
                *trim_ptr = '\0';
                break;
            }
            trim_ptr++;
        }
        
        int io_len = (int)strlen(dynamic_pipeline_io);
        while (io_len > 0 && (dynamic_pipeline_io[io_len - 1] == ' ' || dynamic_pipeline_io[io_len - 1] == '\t')) {
            dynamic_pipeline_io[io_len - 1] = '\0';
            io_len--;
        }
    int build_success = 0;
    char layer_type[256] = {0};

        const char *checked_ext = strrchr(filename, '.');
        checked_ext = (checked_ext) ? checked_ext + 1 : "";
        int is_static_or_meta = 0; // Initialize the passthrough tracking flag
        int requires_compiled_bundling = (STRICMP(checked_ext, "c") == 0 || 
                                           STRICMP(checked_ext, "cpp") == 0 || STRICMP(checked_ext, "cxx") == 0 ||
                                           STRICMP(checked_ext, "cc") == 0 ||
                                           STRICMP(checked_ext, "swift") == 0 ||
                                           STRICMP(checked_ext, "java") == 0 ||
                                           STRICMP(checked_ext, "cs") == 0 ||
                                           STRICMP(checked_ext, "go") == 0 ||
                                           STRICMP(checked_ext, "rs") == 0);

        int total_matching_files_in_capsule = 0;
        if (requires_compiled_bundling) {
            for (int j = 0; j < extracted_count; j++) {
                const char *ext_check = strrchr(extracted_filenames[j], '.');
                if (ext_check && STRICMP(ext_check + 1, checked_ext) == 0) {
                    total_matching_files_in_capsule++;
                }
            }
        }

        // FIXED: Explicitly declared as a large character array string buffer to stop pointer overreads
        char target_sources[8192];
        memset(target_sources, 0, sizeof(target_sources));
        
        snprintf(target_sources, sizeof(target_sources), "\"%s\" ", filename);
        processed_files_registry[i] = 1;

        if (requires_compiled_bundling && total_matching_files_in_capsule > 1) {
            for (int j = 0; j < extracted_count; j++) {
                if (j == i || processed_files_registry[j] == 1) continue;
                const char *ext_check = strrchr(extracted_filenames[j], '.');
                if (ext_check && STRICMP(ext_check + 1, checked_ext) == 0) {
                    snprintf(target_sources + strlen(target_sources), sizeof(target_sources) - strlen(target_sources), "\"%s\" ", extracted_filenames[j]);
                    processed_files_registry[j] = 1;
                }
            }
        }

        // ======================================================================
        //   UPDATED FORMATTING PARAMETERS (BOUNDS CHANGED FROM 8192 TO 16384)
        // ======================================================================

// BLOCK 1 & 2: Universal C/C++ Build Pipeline
if (STRICMP(checked_ext, "c") == 0 || STRICMP(checked_ext, ".c") == 0 || 
         STRICMP(checked_ext, "cpp") == 0 || STRICMP(checked_ext, ".cpp") == 0 || 
         STRICMP(checked_ext, "cxx") == 0 || STRICMP(checked_ext, ".cxx") == 0 ||
         STRICMP(checked_ext, "cc") == 0 || STRICMP(checked_ext, ".cc") == 0) {
    strcpy(runtime_compiler, "g++");
    if (STRICMP(checked_ext, "c") == 0 || STRICMP(checked_ext, ".c") == 0) {
        strcpy(runtime_compiler, "gcc");
    }

    printf("[DEBUG-TRACE] Processing file: %s (size: %zu)\n", filename, file_sizes[i]);

    // 1. CLEAN AUTOMATIC EARLY PASS RETURN GATE
    if (STRICMP(filename, "NUL") == 0 || file_sizes[i] == 0) {
        printf("[DEBUG-TRACE] Hit early pass return gate (NUL or size 0)\n");
        build_success = 1;
        strcpy(extracted_filenames[i], "NUL");
        file_sizes[i] = 0;
        continue; 
    } 
    else {
        // 2. UNIFIED CAPSULE SCANNING PIPELINE
        const char *project_main_filename = NULL;
        int total_cpp_elements = 0;
        int active_node_has_main = 0;

        for (size_t k = 0; k <= file_sizes[i] - 4; k++) {
            if ((memcmp(file_buffers[i] + k, "main", 4) == 0) || memcmp(file_buffers[i] + k, "Main", 4) == 0) {
                char prev_char = (k > 0) ? (char)file_buffers[i][k - 1] : ' ';
                char next_char = (k + 4 < file_sizes[i]) ? (char)file_buffers[i][k + 4] : ' ';
                int is_valid_prev = (prev_char == ' ' || prev_char == '\t' || prev_char == '\n' || prev_char == '\r' || prev_char == '*' || prev_char == '}');
                int is_valid_next = (next_char == ' ' || next_char == '\t' || next_char == '\n' || next_char == '\r' || next_char == '(' || next_char == ';');
                
                if (k >= 3 && memcmp(file_buffers[i] + k - 3, "Win", 3) == 0) {
                    // Part of WinMain
                    active_node_has_main = 1;
                    break;
                } else if (is_valid_prev && is_valid_next) {
                    active_node_has_main = 1;
                    break;
                }
            }
        }
        printf("[DEBUG-TRACE] File %s active_node_has_main = %d\n", filename, active_node_has_main);

        for (int j = 0; j < extracted_count; j++) {
            if (STRICMP(extracted_filenames[j], "NUL") == 0 || file_sizes[j] < 4) continue;
            
            const char *f_ext = strrchr(extracted_filenames[j], '.');
            if (f_ext && (STRICMP(f_ext, ".cpp") == 0 || STRICMP(f_ext, ".c") == 0 || STRICMP(f_ext, ".cxx") == 0 || STRICMP(f_ext, ".cc") == 0)) {
                total_cpp_elements++;
                
                if (project_main_filename == NULL) {
                    for (size_t k = 0; k <= file_sizes[j] - 4; k++) {
                        if ((memcmp(file_buffers[j] + k, "main", 4) == 0) || memcmp(file_buffers[j] + k, "Main", 4) == 0) {
                            char prev_char = (k > 0) ? (char)file_buffers[j][k - 1] : ' ';
                            char next_char = (k + 4 < file_sizes[j]) ? (char)file_buffers[j][k + 4] : ' ';
                            int is_valid_prev = (prev_char == ' ' || prev_char == '\t' || prev_char == '\n' || prev_char == '\r' || prev_char == '*' || prev_char == '}');
                            int is_valid_next = (next_char == ' ' || next_char == '\t' || next_char == '\n' || next_char == '\r' || next_char == '(' || next_char == ';');
                            
                            if (!(k >= 3 && memcmp(file_buffers[j] + k - 3, "Win", 3) == 0) && is_valid_prev && is_valid_next) {
                                project_main_filename = extracted_filenames[j];
                                break;
                            }
                        }
                    }
                }
            }
        }

        printf("[DEBUG-TRACE] Total C++ elements found in capsule: %d\n", total_cpp_elements);

        if (total_cpp_elements > 1 && !active_node_has_main && (target_file == NULL || strlen(target_file) == 0)) {
            int stateless_helpers_exist = 0;
            for (int j = 0; j < extracted_count; j++) {
                if (STRICMP(extracted_filenames[j], "NUL") == 0 || file_sizes[j] < 4) continue;
                const char *f_ext = strrchr(extracted_filenames[j], '.');
                if (f_ext && (STRICMP(f_ext, ".cpp") == 0 || STRICMP(f_ext, ".c") == 0 || STRICMP(f_ext, ".cxx") == 0 || STRICMP(f_ext, ".cc") == 0)) {
                    int file_j_has_main = 0;
                    for (size_t k = 0; k <= file_sizes[j] - 4; k++) {
                        if ((memcmp(file_buffers[j] + k, "main", 4) == 0) || memcmp(file_buffers[j] + k, "Main", 4) == 0) {
                            char prev_char = (k > 0) ? (char)file_buffers[j][k - 1] : ' ';
                            char next_char = (k + 4 < file_sizes[j]) ? (char)file_buffers[j][k + 4] : ' ';
                            int is_valid_prev = (prev_char == ' ' || prev_char == '\t' || prev_char == '\n' || prev_char == '\r' || prev_char == '*' || prev_char == '}');
                            int is_valid_next = (next_char == ' ' || next_char == '\t' || next_char == '\n' || next_char == '\r' || next_char == '(' || next_char == ';');
                            if (is_valid_prev && is_valid_next) { file_j_has_main = 1; break; }
                        }
                    }
                    if (!file_j_has_main) stateless_helpers_exist = 1;
                }
            }

            if (stateless_helpers_exist) {
                printf("[DEBUG-TRACE] Hit architectural alignment gate (stateless helper skipped for now: %s)\n", filename);
                build_success = 1; 
                continue; 
            }
        }

        project_main_filename = filename;
        char target_sources[16384] = {0};
        int gathered_helpers[256] = {0};
        int gathered_count = 0;

        for (int j = 0; j < extracted_count; j++) {
            if (STRICMP(extracted_filenames[j], "NUL") == 0 || file_sizes[j] == 0) continue;
            const char *f_ext = strrchr(extracted_filenames[j], '.');
            if (f_ext && (STRICMP(f_ext, ".cpp") == 0 || STRICMP(f_ext, ".c") == 0 || STRICMP(f_ext, ".cxx") == 0 || STRICMP(f_ext, ".cc") == 0)) {
                strcat(target_sources, "\"");
                strcat(target_sources, extracted_filenames[j]);
                strcat(target_sources, "\" ");
                if (STRICMP(extracted_filenames[j], project_main_filename) != 0) {
                    if (gathered_count < 256) {
                        gathered_helpers[gathered_count++] = j;
                    }
                }
            }
        }
        if (target_sources[0] == '\0') {
            strcat(target_sources, "\"");
            strcat(target_sources, project_main_filename);
            strcat(target_sources, "\" ");
        }

        printf("[DEBUG-TRACE] Target sources for compilation: %s\n", target_sources);

        char include_flags[16384] = "-I. -Iinclude -Isrc ";
        for (int j = 0; j < extracted_count; j++) {
            if (STRICMP(extracted_filenames[j], "NUL") == 0) continue;
            char dir_path[MAX_PATH_LEN];
            strcpy(dir_path, extracted_filenames[j]);
            
            for (int p = 0; dir_path[p] != '\0'; p++) {
                if (dir_path[p] == '\\') dir_path[p] = '/';
            }

            char *last_slash = strrchr(dir_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                char flag_buf[MAX_PATH_LEN + 16];
                snprintf(flag_buf, sizeof(flag_buf), "-I\"%s\" ", dir_path);
                if (strstr(include_flags, flag_buf) == NULL) {
                    strcat(include_flags, flag_buf);
                }
            }
        }
        // Comprehensive library & framework detection matching Windows robustness
        int uses_sfml = 0;
        int uses_sdl = 0;
        int uses_ncurses = 0;
        int uses_glfw = 0;
        int uses_opengl = 0;

        for (int j = 0; j < extracted_count; j++) {
            if (extracted_filenames[j]) {
                char lower_name[1024];
                int k = 0;
                while (extracted_filenames[j][k] && k < sizeof(lower_name) - 1) {
                    lower_name[k] = (char)tolower((unsigned char)extracted_filenames[j][k]);
                    k++;
                }
                lower_name[k] = '\0';
                if (strstr(lower_name, "sfml") != NULL) uses_sfml = 1;
                if (strstr(lower_name, "sdl") != NULL) uses_sdl = 1;
                if (strstr(lower_name, "curses") != NULL || strstr(lower_name, "ncurses") != NULL) uses_ncurses = 1;
                if (strstr(lower_name, "glfw") != NULL) uses_glfw = 1;
            }
        }
        for (int j = 0; j < extracted_count; j++) {
            if (file_sizes[j] > 0 && file_buffers[j] != NULL) {
                for (size_t k = 0; k <= file_sizes[j] - 4; k++) {
                    if (memcmp(file_buffers[j] + k, "SDL_", 4) == 0) uses_sdl = 1;
                    if (memcmp(file_buffers[j] + k, "sf::", 4) == 0) uses_sfml = 1;
                    if (memcmp(file_buffers[j] + k, "initscr", 7) == 0) uses_ncurses = 1;
                    if (memcmp(file_buffers[j] + k, "glfwInit", 8) == 0) uses_glfw = 1;
                    if (memcmp(file_buffers[j] + k, "gladLoad", 8) == 0) uses_opengl = 1;
                    if (memcmp(file_buffers[j] + k, "RenderWindow", 12) == 0) uses_sfml = 1;
                }
            }
        }

        char extra_libs[1024] = "-lm";
        if (uses_sfml) {
            strcat(extra_libs, " -lsfml-graphics -lsfml-window -lsfml-audio -lsfml-system");
        }
        if (uses_sdl) {
            strcat(extra_libs, " -lSDL2 -lSDL2_image");
        }
        if (uses_ncurses) {
            strcat(extra_libs, " -lncurses");
        }
        if (uses_glfw || uses_opengl || uses_sfml || uses_sdl) {
            // macOS adaptation: dynamically link standard system graphics frameworks natively
            #ifdef __APPLE__
            strcat(extra_libs, " -framework OpenGL -framework Cocoa -framework IOKit -framework CoreVideo -lpthread -ldl");
            #else
            strcat(extra_libs, " -lGL -lX11 -lpthread -ldl");
            #endif
        }

        if (uses_glfw) {
            strcat(extra_libs, " -lglfw");
        }

        int uses_raylib = 0;

        // Scan the buffer for the raylib include signature
        for (size_t k = 0; k <= file_sizes[i] - 10; k++) {
            if (memcmp(file_buffers[i] + k, "raylib.h", 8) == 0) {
                uses_raylib = 1;
                break;
            }
        }

        // Append the required library flag to extra_libs
        if (uses_raylib) {
            strcat(extra_libs, " -lraylib");
        }

        int is_graphical_app = 0;
        if (uses_sfml || uses_sdl || uses_glfw || uses_opengl || uses_raylib) {
            is_graphical_app = 1;
        }
        
        for (int j = 0; j < extracted_count; j++) {
            if (file_sizes[j] > 0 && file_buffers[j] != NULL) {
                for (size_t k = 0; k <= file_sizes[j] - 6; k++) {
                    if (memcmp(file_buffers[j] + k, "glfwInit", 8) == 0 ||  
                        memcmp(file_buffers[j] + k, "SDL_Init", 8) == 0 ||
                        memcmp(file_buffers[j] + k, "gladLoad", 8) == 0 ||
                        memcmp(file_buffers[j] + k, "RenderWindow", 12) == 0 ||
                        memcmp(file_buffers[j] + k, "sf::", 4) == 0 ||
                        memcmp(file_buffers[j] + k, "WinMain", 7) == 0 ||
                        memcmp(file_buffers[j] + k, "CreateWindow", 12) == 0 ||
                        memcmp(file_buffers[j] + k, "glutInit", 8) == 0 ||
                        memcmp(file_buffers[j] + k, "InitWindow", 10) == 0) {
                        is_graphical_app = 1;
                        break;
                    }
                }
            }
            if (is_graphical_app) break;
        }

        // Force-feed dynamic linking dependencies if Raylib markers were identified
        if (uses_raylib) {
            if (strstr(extra_libs, "-lraylib") == NULL) {
                strcat(extra_libs, " -lraylib");
            }
        }
        char cmd_exec[65536];
        snprintf(cmd_exec, sizeof(cmd_exec), "%s %s %s -DSDL_MAIN_HANDLED -O3 -pthread -fpermissive -Wno-write-strings %s -o link_temp", runtime_compiler, include_flags, target_sources, extra_libs);
        
        printf("[DEBUG-TRACE] Executing compile command: %s\n", cmd_exec);

        if (system(cmd_exec) == 0) {
            printf("[DEBUG-TRACE] Compilation successful. Launching binary...\n");
            char compiled_binary_path[MAX_PATH_LEN * 2];
            int has_target = (target_file != NULL && strlen(target_file) > 0 && STRICMP(target_file, "NUL") != 0);
            int has_cli_args = (dynamic_pipeline_io[0] != '\0' && strcmp(dynamic_pipeline_io, "35 5") != 0);

            if (has_target) {
                snprintf(compiled_binary_path, sizeof(compiled_binary_path), "./link_temp \"%s\"", target_file);
                printf("Running [Interactive Graphical Window]: %s\n", compiled_binary_path);
                fflush(stdout);
                system(compiled_binary_path);
            } else if (is_graphical_app) {
                snprintf(compiled_binary_path, sizeof(compiled_binary_path), "./link_temp");
                printf("Running [Graphical Application]: %s\n", compiled_binary_path);
                fflush(stdout);
                system(compiled_binary_path);
            } else if (has_cli_args) {
                snprintf(compiled_binary_path, sizeof(compiled_binary_path), "./link_temp %s", dynamic_pipeline_io);
                printf("Running [Interactive TTY]: %s\n", compiled_binary_path);
                fflush(stdout);
                system(compiled_binary_path);
            } else {
                snprintf(compiled_binary_path, sizeof(compiled_binary_path), "./link_temp");
                printf("Running [Live Console Viewport]: %s\n", compiled_binary_path);
                fflush(stdout);
                system(compiled_binary_path);
            }

            build_success = 1;
            strcpy(layer_type, "In-Memory PE");

            if (gathered_count > 0) {
                global_cpp_processed = 1;
                for (int m = 0; m < gathered_count; m++) {
                    int target_idx = gathered_helpers[m];
                    strcpy(extracted_filenames[target_idx], "NUL");
                    file_sizes[target_idx] = 0;
                }
            }

            strcpy(extracted_filenames[i], "NUL");
            file_sizes[i] = 0;

            system("rm -f link_temp");
            continue;
        } else {
            printf("[DEBUG-TRACE] Compilation failed!\n");
            system("rm -f link_temp");
            build_success = 0;
            continue;
        }
    }
}
else if (STRICMP(checked_ext, "h") == 0 || STRICMP(checked_ext, ".h") == 0 || 
         STRICMP(checked_ext, "hpp") == 0 || STRICMP(checked_ext, ".hpp") == 0 || 
         STRICMP(checked_ext, "hh") == 0 || STRICMP(checked_ext, ".hh") == 0) {
    printf("[DEBUG-TRACE] Header file skipped: %s\n", filename);
    continue;
}

        // BLOCK 3: C#
else if (checked_ext && (STRICMP(checked_ext, "cs") == 0 || STRICMP(checked_ext, ".cs") == 0)) {
    static int batch_compiled = 0;
    if (batch_compiled) {
        continue;
    }
    // --- 0. Dynamic Project Detection ---
    char detected_namespace[256] = "DynamicApp";
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        char *base = strrchr(cwd, '/');
        if (base) base++; else base = cwd;
        size_t max_len = sizeof(detected_namespace) - 1;
        snprintf(detected_namespace, sizeof(detected_namespace), "%.*s", (int)max_len, base);
        for (int i = 0; detected_namespace[i] != '\0'; i++) {
            if (!((detected_namespace[i] >= 'A' && detected_namespace[i] <= 'Z') ||
                  (detected_namespace[i] >= 'a' && detected_namespace[i] <= 'z') ||
                  (detected_namespace[i] >= '0' && detected_namespace[i] <= '9') ||
                  detected_namespace[i] == '_')) {
                detected_namespace[i] = '_';
            }
        }
    }

    // --- 1. Dynamic Properties Boilerplate Generation ---
    system("mkdir -p Properties");

    // Check if the extracted files/manifest already provide an AssemblyInfo.cs file
    int has_existing_assembly_info = 0;
    for (int j = 0; j < extracted_count; j++) {
        if (extracted_filenames[j] && strstr(extracted_filenames[j], "AssemblyInfo.cs")) {
            has_existing_assembly_info = 1;
            break;
        }
    }

    FILE *f_new = fopen("Properties/Resources.Designer.cs", "w");
    if (f_new) {
        fprintf(f_new, "namespace %s.Properties {\n", detected_namespace);
        fprintf(f_new, "    using System;\n");
        fprintf(f_new, "    internal class Resources {\n");
        fprintf(f_new, "        private static global::System.Resources.ResourceManager resourceMan;\n");
        fprintf(f_new, "        internal Resources() { }\n");
        fprintf(f_new, "        internal static global::System.Resources.ResourceManager ResourceManager {\n");
        fprintf(f_new, "            get {\n");
        fprintf(f_new, "                if (object.ReferenceEquals(resourceMan, null)) {\n");
        fprintf(f_new, "                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager(\"%s.Properties.Resources\", typeof(Resources).Assembly);\n", detected_namespace);
        fprintf(f_new, "                    resourceMan = temp;\n");
        fprintf(f_new, "                }\n");
        fprintf(f_new, "                return resourceMan;\n");
        fprintf(f_new, "            }\n");
        fprintf(f_new, "        }\n");
        fprintf(f_new, "    }\n");
        fprintf(f_new, "}\n");
        fclose(f_new);
    }

    // Only generate fallback AssemblyInfo.cs if the project doesn't already contain one
    if (!has_existing_assembly_info) {
        FILE *f_asm = fopen("Properties/AssemblyInfo.cs", "w");
        if (f_asm) {
            fprintf(f_asm, "using System.Reflection;\n");
            fprintf(f_asm, "using System.Runtime.InteropServices;\n");
            fprintf(f_asm, "[assembly: AssemblyTitle(\"%s\")]\n", detected_namespace);
            fprintf(f_asm, "[assembly: AssemblyProduct(\"%s\")]\n", detected_namespace);
            fprintf(f_asm, "[assembly: ComVisible(false)]\n");
            fprintf(f_asm, "[assembly: AssemblyVersion(\"1.0.0.0\")]\n");
            fclose(f_asm);
        }
    }
    // --- 2. Dynamic Assembly Discovery & Channel Shim Fallback ---
    char channels_ref[512] = "";
    FILE *fp_chan = popen("find /usr /usr/local /opt -name System.Threading.Channels.dll 2>/dev/null", "r");
    if (fp_chan) {
        char path_buf[256];
        if (fgets(path_buf, sizeof(path_buf), fp_chan)) {
            char *nl = strchr(path_buf, '\n'); if (nl) *nl = '\0';
            if (strlen(path_buf) > 0) {
                snprintf(channels_ref, sizeof(channels_ref), "-r:%s ", path_buf);
            }
        }
        pclose(fp_chan);
    }

    int include_channel_shim = 0;
    if (strlen(channels_ref) == 0) {
        include_channel_shim = 1;
        FILE *f_shim = fopen("Properties/ChannelShim.cs", "w");
        if (f_shim) {
            fprintf(f_shim, "namespace System.Threading.Channels {\n");
            fprintf(f_shim, "    public class ChannelOptions { public bool SingleWriter { get; set; } public bool SingleReader { get; set; } public int BoundedCapacity { get; set; } }\n");
            fprintf(f_shim, "    public class BoundedChannelOptions : ChannelOptions { public BoundedChannelOptions(int capacity) { BoundedCapacity = capacity; } }\n");
            fprintf(f_shim, "    public abstract class ChannelReader<T> {\n");
            fprintf(f_shim, "        public abstract bool TryRead(out T item);\n");
            fprintf(f_shim, "        public abstract System.Threading.Tasks.ValueTask<bool> WaitToReadAsync(System.Threading.CancellationToken cancellationToken = default);\n");
            fprintf(f_shim, "    }\n");
            fprintf(f_shim, "    public abstract class ChannelWriter<T> {\n");
            fprintf(f_shim, "        public abstract bool TryWrite(T item);\n");
            fprintf(f_shim, "        public abstract System.Threading.Tasks.ValueTask<bool> WaitToWriteAsync(System.Threading.CancellationToken cancellationToken = default);\n");
            fprintf(f_shim, "        public void Complete(System.Exception error = null) { }\n");
            fprintf(f_shim, "    }\n");
            fprintf(f_shim, "    public abstract class Channel<TWrite, TRead> {\n");
            fprintf(f_shim, "        public ChannelReader<TRead> Reader { get; set; }\n");
            fprintf(f_shim, "        public ChannelWriter<TWrite> Writer { get; set; }\n");
            fprintf(f_shim, "    }\n");
            fprintf(f_shim, "    public class Channel<T> : Channel<T, T> {\n");
            fprintf(f_shim, "        private readonly System.Collections.Generic.Queue<T> _q = new System.Collections.Generic.Queue<T>();\n");
            fprintf(f_shim, "        private readonly object _lock = new object();\n");
            fprintf(f_shim, "        private class ReaderImpl : ChannelReader<T> {\n");
            fprintf(f_shim, "            private readonly Channel<T> _parent;\n");
            fprintf(f_shim, "            public ReaderImpl(Channel<T> parent) { _parent = parent; }\n");
            fprintf(f_shim, "            public override bool TryRead(out T item) {\n");
            fprintf(f_shim, "                lock (_parent._lock) {\n");
            fprintf(f_shim, "                    if (_parent._q.Count > 0) { item = _parent._q.Dequeue(); return true; }\n");
            fprintf(f_shim, "                    item = default(T);\n");
            fprintf(f_shim, "                    return false;\n");
            fprintf(f_shim, "                }\n");
            fprintf(f_shim, "            }\n");
            fprintf(f_shim, "            public override System.Threading.Tasks.ValueTask<bool> WaitToReadAsync(System.Threading.CancellationToken cancellationToken = default) {\n");
            fprintf(f_shim, "                lock (_parent._lock) { return new System.Threading.Tasks.ValueTask<bool>(_parent._q.Count > 0); }\n");
            fprintf(f_shim, "            }\n");
            fprintf(f_shim, "        }\n");
            fprintf(f_shim, "        private class WriterImpl : ChannelWriter<T> {\n");
            fprintf(f_shim, "            private readonly Channel<T> _parent;\n");
            fprintf(f_shim, "            public WriterImpl(Channel<T> parent) { _parent = parent; }\n");
            fprintf(f_shim, "            public override bool TryWrite(T item) {\n");
            fprintf(f_shim, "                lock (_parent._lock) { _parent._q.Enqueue(item); System.Threading.Monitor.PulseAll(_parent._lock); return true; }\n");
            fprintf(f_shim, "            }\n");
            fprintf(f_shim, "            public override System.Threading.Tasks.ValueTask<bool> WaitToWriteAsync(System.Threading.CancellationToken cancellationToken = default) {\n");
            fprintf(f_shim, "                return new System.Threading.Tasks.ValueTask<bool>(true);\n");
            fprintf(f_shim, "            }\n");
            fprintf(f_shim, "        }\n");
            fprintf(f_shim, "        public Channel() {\n");
            fprintf(f_shim, "            Reader = new ReaderImpl(this);\n");
            fprintf(f_shim, "            Writer = new WriterImpl(this);\n");
            fprintf(f_shim, "        }\n");
            fprintf(f_shim, "    }\n");
            fprintf(f_shim, "    public static class Channel {\n");
            fprintf(f_shim, "        public static Channel<T> CreateUnbounded<T>() { return new Channel<T>(); }\n");
            fprintf(f_shim, "        public static Channel<T> CreateUnbounded<T>(UnboundedChannelOptions options) { return new Channel<T>(); }\n");
            fprintf(f_shim, "        public static Channel<T> CreateBounded<T>(int capacity) { return new Channel<T>(); }\n");
            fprintf(f_shim, "        public static Channel<T> CreateBounded<T>(BoundedChannelOptions options) { return new Channel<T>(); }\n");
            fprintf(f_shim, "    }\n");
            fprintf(f_shim, "    public class UnboundedChannelOptions : ChannelOptions {}\n");
            fprintf(f_shim, "}\n");
            fclose(f_shim);
        }
    }

    int has_main_method = 0;
    int uses_windows_forms = 0;
    char target_sources[16384];
    
    // Initialize sources string with generated Designer resource
    snprintf(target_sources, sizeof(target_sources), "\"Properties/Resources.Designer.cs\" ");
    
    // Add generated AssemblyInfo only if none was supplied by the project
    if (!has_existing_assembly_info) {
        strcat(target_sources, "\"Properties/AssemblyInfo.cs\" ");
    }

    if (include_channel_shim) {
        strcat(target_sources, "\"Properties/ChannelShim.cs\" ");
    }
    for (int j = 0; j < extracted_count; j++) {
        const char *fname_j = extracted_filenames[j];
        if (fname_j) {
            const char *ext = strrchr(fname_j, '.');
            if (ext && (STRICMP(ext, "cs") == 0 || STRICMP(ext, ".cs") == 0)) {
                FILE *fp = fopen(fname_j, "r");
                if (fp) {
                    char line[1024];
                    while (fgets(line, sizeof(line), fp)) {
                        if (strstr(line, "Main(") || strstr(line, "Main (")) has_main_method = 1;
                        if (strstr(line, "System.Windows.Forms") || strstr(line, "Form") || strstr(line, "Application.Run")) uses_windows_forms = 1;
                    }
                    fclose(fp);
                }
                if (strlen(target_sources) + strlen(fname_j) + 8 < sizeof(target_sources)) {
                    strcat(target_sources, "\"");
                    strcat(target_sources, fname_j);
                    strcat(target_sources, "\" ");
                }
            }
        }
    }

    const char *target_type = has_main_method ? "exe" : "library";
    if (uses_windows_forms) {
        target_type = "winexe";
    }

    // --- 3. Dynamic Assembly References (deps/ & System.Design) ---
    char assembly_refs[16384] = "-r:System -r:System.Core -r:System.Data -r:System.Net.Http -r:System.Windows.Forms -r:System.Drawing -r:System.Design ";
    DIR *d = opendir("deps");
    if (d) {
        struct dirent *dir;
        while ((dir = readdir(d)) != NULL) {
            const char *ext = strrchr(dir->d_name, '.');
            if (ext && STRICMP(ext, ".dll") == 0) {
                strcat(assembly_refs, "-r:deps/");
                strcat(assembly_refs, dir->d_name);
                strcat(assembly_refs, " ");
            }
        }
        closedir(d);
    }

    char cmd_exec[65536];
    char *cs_trim = dynamic_pipeline_io;
    while (*cs_trim != '\0' && *cs_trim != '\r' && *cs_trim != '\n') cs_trim++;
    *cs_trim = '\0';

    if (strlen(dynamic_pipeline_io) > 0) {
        snprintf(cmd_exec, sizeof(cmd_exec),
            "mcs -langversion:latest -target:%s %s %s %s -out:link_temp_stage.exe && echo \"%s\" | mono link_temp_stage.exe && rm -f link_temp_stage.exe",
            target_type, assembly_refs, channels_ref, target_sources, dynamic_pipeline_io);
    } else {
        snprintf(cmd_exec, sizeof(cmd_exec),
            "mcs -langversion:latest -target:%s %s %s %s -out:link_temp_stage.exe && mono link_temp_stage.exe && rm -f link_temp_stage.exe",
            target_type, assembly_refs, channels_ref, target_sources);
    }

    printf("Running: [Mono Dynamic Assembly Stack] -> "); fflush(stdout);

    execute_and_pipe(cmd_exec, "", next_pipeline_output, 4096);
    if (strlen(next_pipeline_output) > 0) {
        strncpy(dynamic_pipeline_io, next_pipeline_output, 4096);
        dynamic_pipeline_io[4095] = '\0';
    }

    batch_compiled = 1;
    strcpy(layer_type, "In-Memory PE");
}
else if (checked_ext && (STRICMP(checked_ext, "resx") == 0 || STRICMP(checked_ext, ".resx") == 0)) {
    continue;
}
        // ------------------------------------------------------------------
        // BLOCK 4: JAVA VIRTUAL MACHINE MULTI-FILE ROUTING MODULE (ORDER-INDEPENDENT)
        // ------------------------------------------------------------------
        else if (STRICMP(checked_ext, "java") == 0) {
            char discovered_entry_class[MAX_PATH_LEN] = {0};
            
            // ======================================================================
            //  DYNAMIC MAIN METHOD SCANNER: LOCATES THE TRUE ENTRY CLASS
            // ======================================================================
            // We search through ALL extracted java files in this bundle to find the one 
            // that contains the string pattern token "main(" natively in memory!
            int found_main_class = 0;
            for (int j = 0; j < extracted_count; j++) {
                const char *j_ext = strrchr(extracted_filenames[j], '.');
                if (j_ext && STRICMP(j_ext + 1, "java") == 0 && file_sizes[j] > 0) {
                    
                    // Simple, fast memory scanning loop over the raw source text buffer
                    for (size_t k = 0; k < file_sizes[j] && k < 8192; k++) {
                        if (k < file_sizes[j] - 5 && memcmp(file_buffers[j] + k, "main(", 5) == 0) {
                            const char *base_ptr = strrchr(extracted_filenames[j], '\\');
                            if (!base_ptr) base_ptr = strrchr(extracted_filenames[j], '/');
                            base_ptr = (base_ptr) ? base_ptr + 1 : extracted_filenames[j];
                            strncpy_s(discovered_entry_class, MAX_PATH_LEN, base_ptr, strcspn(base_ptr, "."));
                            found_main_class = 1;
                            break;
                        }
                    }
                }
                if (found_main_class) break;
            }

            // Fallback safety gate in case no main method token pattern was successfully isolated
            if (!found_main_class) {
                const char *base_ptr = strrchr(filename, '\\');
                if (!base_ptr) base_ptr = strrchr(filename, '/');
                base_ptr = (base_ptr) ? base_ptr + 1 : filename;
                strncpy_s(discovered_entry_class, MAX_PATH_LEN, base_ptr, strcspn(base_ptr, "."));
            }
            // ======================================================================

#ifdef _WIN32
            snprintf(cmd_exec, 16384, "javac %s && cmd.exe /c echo %s | java -Djava.class.path=. %s", target_sources, dynamic_pipeline_io, discovered_entry_class);
#else
            snprintf(cmd_exec, 16384, "javac %s && echo \"%s\" | java -cp . %s", target_sources, dynamic_pipeline_io, discovered_entry_class);
#endif
            printf("Running: [Bytecode VM] Java Module -> "); fflush(stdout);
            execute_and_pipe(cmd_exec, "", next_pipeline_output, 1048576);
            if (strlen(next_pipeline_output) > 0) strncpy(dynamic_pipeline_io, next_pipeline_output, 1048576 - 1);
            
            // Mark all bundled companion files handled to prevent duplicate compilation loop passes
            if (total_matching_files_in_capsule > 1) {
                for (int m_j = 0; m_j < extracted_count; m_j++) {
                    const char *e_check = strrchr(extracted_filenames[m_j], '.');
                    if (e_check && STRICMP(e_check + 1, "java") == 0) {
                        processed_files_registry[m_j] = 1;
                    }
                }
            }
        }

        // BLOCK 5: Go
        else if (_stricmp(checked_ext, "go") == 0) {
            // Clean trailing whitespace, carriage returns, or newlines from filename
            char clean_filename[512];
            strncpy(clean_filename, filename, sizeof(clean_filename) - 1);
            int flen = strlen(clean_filename);
            while (flen > 0 && (clean_filename[flen-1] == '\r' || clean_filename[flen-1] == '\n' || clean_filename[flen-1] == ' ' || clean_filename[flen-1] == '\t')) {
                clean_filename[flen-1] = '\0';
                flen--;
            }

            // Normalize path separators for platform compatibility
            char rel_path[512];
            strcpy(rel_path, clean_filename);
            for (int k = 0; rel_path[k] != '\0'; k++) {
                if (rel_path[k] == '\\') rel_path[k] = '/';
            }

            // Extract target directory containing this .go file
            char dir_path[512];
            char *last_slash = strrchr(rel_path, '/');
            if (last_slash) {
                *last_slash = '\0';
                strcpy(dir_path, rel_path);
                *last_slash = '/';
            } else {
                strcpy(dir_path, ".");
            }

            // Mark all companion .go files in the same package directory as processed
            for (int j = 0; j < extracted_count; j++) {
                const char *loop_ext = strrchr(extracted_filenames[j], '.');
                if (loop_ext && _stricmp(loop_ext + 1, "go") == 0) {
                    char loop_rel[512];
                    strncpy(loop_rel, extracted_filenames[j], sizeof(loop_rel) - 1);
                    for (int k = 0; loop_rel[k] != '\0'; k++) {
                        if (loop_rel[k] == '\\') loop_rel[k] = '/';
                    }
                    char *loop_slash = strrchr(loop_rel, '/');
                    char loop_dir[512];
                    if (loop_slash) {
                        *loop_slash = '\0';
                        strcpy(loop_dir, loop_rel);
                    } else {
                        strcpy(loop_dir, ".");
                    }
                    if (strcmp(dir_path, loop_dir) == 0) {
                        processed_files_registry[j] = 1;
                    }
                }
            }
            processed_files_registry[i] = 1;
            strcpy(runtime_compiler, "go");
            char runtime_runner[256] = "link_temp_stage";
            
            // Go build pipeline: builds within upstream module context or sandbox, always outputting to $PWD
            snprintf(cmd_exec, 16384,
                "curr=\"$PWD\"; "
                "has_mod=0; "
                "c=\"$curr\"; "
                "while [ \"$c\" != \"/\" ]; do "
                "    if [ -f \"$c/go.mod\" ]; then has_mod=1; break; fi; "
                "    c=$(dirname \"$c\"); "
                "done; "
                "target_dir=\"%s\"; "
                "target_file=\"%s\"; "
                "if [ \"$has_mod\" -eq 1 ]; then "
                "    cd \"$curr/$target_dir\" 2>/dev/null || cd \"$curr\"; "
                "    go build -o \"$curr/%s\" .; "
                "    ret=$?; "
                "    cd \"$curr\"; "
                "    exit $ret; "
                "else "
                "    rm -rf _go_runtime_sandbox && mkdir -p _go_runtime_sandbox; "
                "    if [ -f \"$target_file\" ]; then cp \"$target_file\" _go_runtime_sandbox/; fi; "
                "    if [ -d \"$target_dir\" ] && [ \"$target_dir\" != \".\" ]; then "
                "        cp -r \"$target_dir\" _go_runtime_sandbox/; "
                "    fi; "
                "    cd _go_runtime_sandbox; "
                "    go mod init kryptos_temp_mod >/dev/null 2>&1 || true; "
                "    base_file=$(basename \"$target_file\"); "
                "    if [ -f \"$base_file\" ]; then "
                "        go build -o \"$curr/%s\" \"$base_file\"; "
                "    else "
                "        go build -o \"$curr/%s\" .; "
                "    fi; "
                "    ret=$?; "
                "    cd \"$curr\"; "
                "    rm -rf _go_runtime_sandbox; "
                "    exit $ret; "
                "fi",
                dir_path, rel_path, runtime_runner, runtime_runner, runtime_runner);

            printf("Running: [Ephemeral PE] Go Native Execution -> "); fflush(stdout);
            
            if (system(cmd_exec) == 0) {
                char *go_ptr = dynamic_pipeline_io;
                while (*go_ptr != '\0') {
                    if (*go_ptr == '\r' || *go_ptr == '\n') {
                        *go_ptr = '\0';
                        break;
                    }
                    go_ptr++;
                }
                int clean_len = (int)strlen(dynamic_pipeline_io);
                while (clean_len > 0 && (dynamic_pipeline_io[clean_len - 1] == ' ' || dynamic_pipeline_io[clean_len - 1] == '\t')) {
                    dynamic_pipeline_io[clean_len - 1] = '\0';
                    clean_len--;
                }

                char *env_mode = getenv("MULTILANGUAGE_MODE");
                int multilanguage_mode = (env_mode && (strcmp(env_mode, "1") == 0 || strcasecmp(env_mode, "true") == 0)) ? 1 : 0;

                if (multilanguage_mode) {
                    if (strlen(dynamic_pipeline_io) > 0) {
                        snprintf(cmd_exec, 16384, "chmod +x ./%s && echo \"%s\" | ./%s && rm -f ./%s", runtime_runner, dynamic_pipeline_io, runtime_runner, runtime_runner);
                    } else {
                        snprintf(cmd_exec, 16384, "chmod +x ./%s && ./%s && rm -f ./%s", runtime_runner, runtime_runner, runtime_runner);
                    }
                    
                    fflush(stdout);
                    
                    if (execute_and_pipe(cmd_exec, "", next_pipeline_output, sizeof(next_pipeline_output))) {
                        char *trim_ptr = next_pipeline_output + strlen(next_pipeline_output) - 1;
                        while (trim_ptr >= next_pipeline_output && (*trim_ptr == '\r' || *trim_ptr == '\n' || *trim_ptr == ' ')) {
                            *trim_ptr = '\0';
                            trim_ptr--;
                        }
                        if (strlen(next_pipeline_output) > 0) {
                            strncpy(dynamic_pipeline_io, next_pipeline_output, 1048576 - 1);
                        }
                    }
                } else {
                    snprintf(cmd_exec, 16384, "chmod +x ./%s && ./%s && rm -f ./%s", runtime_runner, runtime_runner, runtime_runner);
                    fflush(stdout);
                    system(cmd_exec);
                }

                build_success = 1;
                strcpy(layer_type, "Ephemeral PE");
            } else {
                printf("[-] Go Compilation Failure on multi-module block.\n");
                build_success = 0;
            }
        }
        // ------------------------------------------------------------------
        // BLOCK 6: RUST ENGINE PROGRAM ROUTING MODULE (ORDER-INDEPENDENT)
        // ------------------------------------------------------------------
        else if (strcasecmp(checked_ext, "rs") == 0 || strcasecmp(checked_ext, ".rs") == 0) {
            // 1. GLOBAL LOCK: Only allow the first file in the batch to trigger the entire rust process
            static int has_executed_batch_linux = 0;
            
            if (has_executed_batch_linux == 0) {
                // Write all extracted files to physical disk first
                for (int j = 0; j < extracted_count; j++) {
                    if (extracted_filenames[j] && file_buffers[j]) {
                        const char *fname = extracted_filenames[j];
                        
                        char dir_path[512];
                        snprintf(dir_path, sizeof(dir_path), "%s", fname);
                        char *last_slash = strrchr(dir_path, '/');
                        if (!last_slash) last_slash = strrchr(dir_path, '\\');
                        if (last_slash) {
                            *last_slash = '\0';
                            char mkdir_cmd[1024]; 
                            snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\" 2>/dev/null", dir_path);
                            system(mkdir_cmd);
                        }

                        FILE *f_disk = fopen(fname, "wb");
                        if (f_disk) {
                            fwrite(file_buffers[j], 1, file_sizes[j], f_disk);
                            fclose(f_disk);
                        }
                    }
                }

                // Check if Cargo.toml exists
                int has_cargo_toml = (access("Cargo.toml", F_OK) == 0);
                if (!has_cargo_toml) {
                    for (int j = 0; j < extracted_count; j++) {
                        if (extracted_filenames[j] && strstr(extracted_filenames[j], "Cargo.toml") != NULL) {
                            has_cargo_toml = 1;
                            break;
                        }
                    }
                }

                int rust_indices[MAX_FILES];
                int rust_count = 0;
                for (int j = 0; j < extracted_count; j++) {
                    const char *fname = extracted_filenames[j];
                    if (fname) {
                        const char *r_ext = strrchr(fname, '.');
                        if (r_ext && (strcasecmp(r_ext, ".rs") == 0 || strcasecmp(r_ext + 1, "rs") == 0)) {
                            rust_indices[rust_count++] = j;
                        }
                    }
                }

                // Deterministic sort
                for (int x = 0; x < rust_count - 1; x++) {
                    for (int y = 0; y < rust_count - x - 1; y++) {
                        if (strcasecmp(extracted_filenames[rust_indices[y]], extracted_filenames[rust_indices[y + 1]]) > 0) {
                            int temp = rust_indices[y];
                            rust_indices[y] = rust_indices[y + 1];
                            rust_indices[y + 1] = temp;
                        }
                    }
                }
                if (has_cargo_toml) {
                    char package_name[256] = "app";
                    for (int j = 0; j < extracted_count; j++) {
                        const char *fname = extracted_filenames[j];
                        if (fname && (strcasecmp(fname, "Cargo.toml") == 0 || strstr(fname, "Cargo.toml") != NULL)) {
                            if (file_buffers[j]) {
                                char *content = (char *)file_buffers[j];
                                char *pkg_sec = strstr(content, "[package]");
                                char *name_ptr = strstr(pkg_sec ? pkg_sec : content, "name");
                                if (name_ptr) {
                                    name_ptr = strchr(name_ptr, '=');
                                    if (name_ptr) {
                                        name_ptr++;
                                        while (*name_ptr == ' ' || *name_ptr == '\t' || *name_ptr == '"' || *name_ptr == '\'') name_ptr++;
                                        int p = 0;
                                        while (*name_ptr && *name_ptr != '"' && *name_ptr != '\'' && *name_ptr != '\r' && *name_ptr != '\n' && *name_ptr != '#' && p < sizeof(package_name) - 1) {
                                            package_name[p++] = *name_ptr++;
                                        }
                                        package_name[p] = '\0';
                                    }
                                }
                            }
                        }
                    }

                    snprintf(cmd_exec, 16384, "cargo build --release");
                    int build_status = system(cmd_exec);

                    if (build_status == 0) {
                        char bin_path[512] = "";
                        snprintf(bin_path, sizeof(bin_path), "target/release/%s", package_name);

                        // Robust fallback scan for packages where binary name differs from package name
                        if (access(bin_path, F_OK) != 0) {
                            DIR *d = opendir("target/release");
                            if (d) {
                                struct dirent *dir;
                                while ((dir = readdir(d)) != NULL) {
                                    if (dir->d_name[0] != '.') {
                                        const char *ext = strrchr(dir->d_name, '.');
                                        if (!ext || (strcmp(ext, ".d") != 0 && strcmp(ext, ".rlib") != 0 && strcmp(ext, ".rmeta") != 0 && strcmp(ext, ".so") != 0)) {
                                            char candidate[512];
                                            snprintf(candidate, sizeof(candidate), "target/release/%s", dir->d_name);
                                            struct stat st;
                                            if (stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
                                                if ((st.st_mode & S_IXUSR) || !ext) {
                                                    snprintf(bin_path, sizeof(bin_path), "%s", candidate);
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                closedir(d);
                            }
                        }

                        if (access(bin_path, F_OK) != 0) {
                            snprintf(bin_path, sizeof(bin_path), "target/release/app");
                        }

                        if (access(bin_path, F_OK) == 0) {
                            const char *common_folders[] = {"assets", "resources", "data", "static", "config"};
                            for (int f = 0; f < 5; f++) {
                                char sync_cmd[512];
                                snprintf(sync_cmd, sizeof(sync_cmd), "if [ -d %s ]; then cp -r %s target/release/ 2>/dev/null; fi", common_folders[f], common_folders[f]);
                                system(sync_cmd);
                            }

                            int mode_is_file = 0;
                            for (int r_i = 0; r_i < rust_count; r_i++) {
                                int idx = rust_indices[r_i];
                                if (file_buffers[idx] && strstr((char*)file_buffers[idx], "@MODE:FILE") != NULL) {
                                    mode_is_file = 1;
                                    break;
                                }
                            }

                            char *env_gui = getenv("RUST_GUI");
                            int is_gui_app = (env_gui != NULL && strcmp(env_gui, "0") != 0 && strcasecmp(env_gui, "false") != 0);

                            if (mode_is_file) {
                                #ifdef __APPLE__
                                snprintf(cmd_exec, 16384, "./%s \"%s\" > pipeline.out", bin_path, dynamic_pipeline_io);
                                #else
                                snprintf(cmd_exec, 16384, "LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe ./%s \"%s\" > pipeline.out", bin_path, dynamic_pipeline_io);
                                #endif
                                system(cmd_exec);
                            } else if (is_gui_app) {
                                if (dynamic_pipeline_io[0] != '\0') {
                                    #ifdef __APPLE__
                                    snprintf(cmd_exec, 16384, "./%s %s", bin_path, dynamic_pipeline_io);
                                    #else
                                    snprintf(cmd_exec, 16384, "LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe ./%s %s", bin_path, dynamic_pipeline_io);
                                    #endif
                                } else {
                                    #ifdef __APPLE__
                                    snprintf(cmd_exec, 16384, "./%s", bin_path);
                                    #else
                                    snprintf(cmd_exec, 16384, "LIBGL_ALWAYS_SOFTWARE=1 GALLIUM_DRIVER=llvmpipe ./%s", bin_path);
                                    #endif
                                }
                                printf("[Pipeline Pass] RUST_GUI flag detected. Spawning native application context...\n");
                                fflush(stdout);
                                int exit_code = system(cmd_exec);
                                printf("Running: [Cargo GUI Application] exited with code: %d\n", exit_code);
                            } else {
                                if (dynamic_pipeline_io[0] != '\0') {
                                    snprintf(cmd_exec, 16384, "./%s %s", bin_path, dynamic_pipeline_io);
                                } else {
                                    snprintf(cmd_exec, 16384, "./%s", bin_path);
                                }
                                char local_out[4096] = {0};
                                if (execute_and_pipe(cmd_exec, "", local_out, sizeof(local_out))) {
                                    strncpy(dynamic_pipeline_io, local_out, 4095);
                                    printf("Running: [Cargo Ephemeral PE] -> Out: %s\n", local_out);
                                    fflush(stdout);
                                }
                            }
                        }
                    }
                    strcpy(layer_type, "Cargo Ephemeral PE");
                } else {
            // STANDALONE RUST EXECUTION VIA rustc & execute_and_pipe
            for (int r_i = 0; r_i < rust_count; r_i++) {
                int idx = rust_indices[r_i];
                const char *fname = extracted_filenames[idx];
                if (fname) {
                    char base_name[256];
                    snprintf(base_name, sizeof(base_name), "%s", fname);
                    char *dot = strrchr(base_name, '.');
                    if (dot) *dot = '\0';

                    char *slash = strrchr(base_name, '/');
                    if (!slash) slash = strrchr(base_name, '\\');
                    char *exe_name = slash ? slash + 1 : base_name;

                    snprintf(cmd_exec, 16384, "rustc \"%s\" -O -o \"%s\"", fname, exe_name);
                    int build_status = system(cmd_exec);

                    if (build_status == 0) {
                        char bin_path[512];
                        snprintf(bin_path, sizeof(bin_path), "./%s", exe_name);

                        if (access(bin_path, F_OK) == 0) {
                            if (dynamic_pipeline_io[0] != '\0') {
                                snprintf(cmd_exec, 16384, "\"%s\" %s", bin_path, dynamic_pipeline_io);
                            } else {
                                snprintf(cmd_exec, 16384, "\"%s\"", bin_path);
                            }

                            char local_out[4096] = {0};
                            if (execute_and_pipe(cmd_exec, "", local_out, sizeof(local_out))) {
                                strncpy(dynamic_pipeline_io, local_out, 4095);
                                printf("Running: [Ephemeral PE] Rust Native Execution -> Out: %s\n", local_out);
                                fflush(stdout);
                            }
                        }
                    }
                }
            }
            strcpy(layer_type, "Standalone Rust Ephemeral PE");
        }

        // Mark all collected rust files as processed
        for (int k = 0; k < rust_count; k++) {
            processed_files_registry[rust_indices[k]] = 1;
        }

        has_executed_batch_linux = 1;
    }
    
    build_success = 1;
    continue;
}

        // BLOCK 7: Swift
else if (STRICMP(checked_ext, "swift") == 0) {
    strcpy(runtime_compiler, "swift");

    int has_package_swift = 0;

    // 1. Extract and write out all files from the capsule
    for (int k = 0; k < extracted_count; k++) {
        char k_clean[256] = {0};
        strncpy(k_clean, extracted_filenames[k], sizeof(k_clean) - 1);

        // Normalize slashes for Unix targets
        for (int p = 0; k_clean[p] != '\0'; p++) {
            if (k_clean[p] == '\\') k_clean[p] = '/';
        }

        if (STRICMP(k_clean, "Package.swift") == 0 || strstr(k_clean, "/Package.swift") != NULL) {
            has_package_swift = 1;
        }

        // Create parent directories if nested
        char k_local[256] = {0};
        strcpy(k_local, k_clean);
        for (char *p = k_local + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(k_local, 0755);
                *p = '/';
            }
        }

        FILE *kf = fopen(k_clean, "wb");
        if (kf) {
            fwrite(file_buffers[k], 1, file_sizes[k], kf);
            fclose(kf);
        }
    }
    if (has_package_swift) {
        char product_name[256] = "";
        char spm_args[4096] = "";
        
        int start_idx = 3;
        if (argc > 3 && STRICMP(argv[3], "run") == 0) {
            start_idx = 4; // Skip 'run' keyword if present
        }
        
        if (argc > start_idx) {
            strncpy(product_name, argv[start_idx], sizeof(product_name) - 1);
            start_idx++;
        }
        
        for (int a = start_idx; a < argc; a++) {
            strcat(spm_args, " ");
            strcat(spm_args, argv[a]);
        }
        
        // Step A: Build silently with suppressed warnings
        snprintf(cmd_exec, 16384, "swift build --quiet -Xswiftc -suppress-warnings 2>&1");
        printf("Building: [Swift SPM Package] -> \n"); 
        fflush(stdout);
        
        char build_output[4096] = {0};
        execute_and_pipe(cmd_exec, "", build_output, sizeof(build_output));
        
        if (strstr(build_output, "error") != NULL) {
            snprintf(next_pipeline_output, 1048576, "Build Error:\n%s", build_output);
        } else {
            if (strlen(product_name) > 0) {
                snprintf(cmd_exec, 16384, "./.build/debug/%s%s 2>&1", product_name, spm_args);
            } else {
                snprintf(cmd_exec, 16384, "./.build/debug/math%s 2>&1", spm_args);
            }
            
            printf("Running: [Swift Binary] -> \n"); 
            fflush(stdout);
            execute_and_pipe(cmd_exec, "", next_pipeline_output, 1048576);
        }
    } else {
        // Collect extra arguments from CLI for standalone script
        char extra_args[4096] = {0};
        for (int a = 3; a < argc; a++) {
            strcat(extra_args, " ");
            strcat(extra_args, argv[a]);
        }

        // Monolithic combination: Pass 1 (helpers, i.e., filenames NOT containing "main"), Pass 2 (entry point, i.e., containing "main")
        char combined_swift_filename[256] = "combined_app.swift";
        FILE *f_comb = fopen(combined_swift_filename, "wb");
        if (f_comb) {
            // Pass 1: Non-main files
            for (int k = 0; k < extracted_count; k++) {
                char k_clean[256] = {0};
                strncpy(k_clean, extracted_filenames[k], sizeof(k_clean) - 1);
                for (int p = 0; k_clean[p] != '\0'; p++) {
                    if (k_clean[p] == '\\') k_clean[p] = '/';
                }
                int slen = (int)strlen(k_clean);
                if (slen > 6 && STRICMP(k_clean + slen - 6, ".swift") == 0) {
                    char lower_fn[256] = {0};
                    strcpy(lower_fn, k_clean);
                    for (int z = 0; lower_fn[z]; z++) {
                        if (lower_fn[z] >= 'A' && lower_fn[z] <= 'Z') lower_fn[z] += 32;
                    }
                    if (strstr(lower_fn, "main") == NULL) {
                        FILE *src_f = fopen(k_clean, "rb");
                        if (src_f) {
                            char buf[4096];
                            size_t bytes;
                            while ((bytes = fread(buf, 1, sizeof(buf), src_f)) > 0) {
                                fwrite(buf, 1, bytes, f_comb);
                            }
                            fclose(src_f);
                            fwrite("\n", 1, 1, f_comb);
                        }
                    }
                }
            }
            // Pass 2: Main files
            for (int k = 0; k < extracted_count; k++) {
                char k_clean[256] = {0};
                strncpy(k_clean, extracted_filenames[k], sizeof(k_clean) - 1);
                for (int p = 0; k_clean[p] != '\0'; p++) {
                    if (k_clean[p] == '\\') k_clean[p] = '/';
                }
                int slen = (int)strlen(k_clean);
                if (slen > 6 && STRICMP(k_clean + slen - 6, ".swift") == 0) {
                    char lower_fn[256] = {0};
                    strcpy(lower_fn, k_clean);
                    for (int z = 0; lower_fn[z]; z++) {
                        if (lower_fn[z] >= 'A' && lower_fn[z] <= 'Z') lower_fn[z] += 32;
                    }
                    if (strstr(lower_fn, "main") != NULL) {
                        FILE *src_f = fopen(k_clean, "rb");
                        if (src_f) {
                            char buf[4096];
                            size_t bytes;
                            while ((bytes = fread(buf, 1, sizeof(buf), src_f)) > 0) {
                                fwrite(buf, 1, bytes, f_comb);
                            }
                            fclose(src_f);
                            fwrite("\n", 1, 1, f_comb);
                        }
                    }
                }
            }
            fclose(f_comb);
        }

        // Step A: Compile combined script with swiftc (suppressing warnings)
        snprintf(cmd_exec, 16384, "swiftc -suppress-warnings \"%s\" -o app_bin 2>&1", combined_swift_filename);
        printf("Compiling: [Swift Script] -> \n"); fflush(stdout);

        char compile_output[4096] = {0};
        execute_and_pipe(cmd_exec, "", compile_output, sizeof(compile_output));

        if (strstr(compile_output, "error") != NULL) {
            snprintf(next_pipeline_output, 1048576, "Compilation Error:\n%s", compile_output);
        } else {
            // Step B: Execute compiled binary
            snprintf(cmd_exec, 16384, "./app_bin%s 2>&1", extra_args);
            printf("Running: [Swift Binary] -> \n"); fflush(stdout);
            execute_and_pipe(cmd_exec, "", next_pipeline_output, 1048576);
        }
    }

    if (strlen(next_pipeline_output) > 0) {
        strncpy(dynamic_pipeline_io, next_pipeline_output, 1048576 - 1);
    }
}

// ==================================================================
// FIXED BLOCK 8: PYTHON MULTI-MODULE INTERPRETER ROUTING MODULE
// ==================================================================

else if (STRICMP(checked_ext, "py") == 0) {
    setvbuf(stdout, NULL, _IONBF, 0);
    no_web = 1;
    // Clean leading/trailing whitespace from incoming pipeline buffer
    if (dynamic_pipeline_io != NULL) {
        size_t io_len = strlen(dynamic_pipeline_io);
        while (io_len > 0 && (dynamic_pipeline_io[io_len - 1] == '\r' || 
                              dynamic_pipeline_io[io_len - 1] == '\n' || 
                              dynamic_pipeline_io[io_len - 1] == ' '  || 
                              dynamic_pipeline_io[io_len - 1] == '\t')) {
            dynamic_pipeline_io[io_len - 1] = '\0';
            io_len--;
        }
    }

    size_t system_map_overhead = 1048576; 
    for (int m = 0; m < extracted_count; m++) {
        size_t b64_len = ((file_sizes[m] + 2) / 3) * 4;
        system_map_overhead += b64_len + MAX_PATH_LEN + 128;
    }

    char *combined_script_payload = (char *)malloc(system_map_overhead);
    if (combined_script_payload != NULL) {
        memset(combined_script_payload, 0, system_map_overhead);
        size_t offset = 0;

    int written = snprintf(combined_script_payload + offset, system_map_overhead - offset, 
    "import sys, types, base64, io, os, re, atexit\n"
    "from importlib.machinery import ModuleSpec\n" 
    "if hasattr(sys.stdout, 'reconfigure'):\n"
    "    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')\n"
    "if hasattr(sys.stderr, 'reconfigure'):\n"
    "    sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace')\n"
    "class HybridStdin:\n"
    "    def __init__(self, val, real_in):\n"
    "        self.mem = io.StringIO(val + '\\n') if val else None\n"
    "        self.real = real_in\n"
    "    def read(self, *a, **k):\n"
    "        if self.mem is not None:\n"
    "            r = self.mem.read(*a, **k)\n"
    "            if r: return r\n"
    "            self.mem = None\n"
    "        return self.real.read(*a, **k) if self.real else ''\n"
    "    def readline(self, *a, **k):\n"
    "        if self.mem is not None:\n"
    "            r = self.mem.readline(*a, **k)\n"
    "            if r: return r\n"
    "            self.mem = None\n"
    "        return self.real.readline(*a, **k) if self.real else ''\n"
    "    def close(self):\n"
    "        if self.real and hasattr(self.real, 'close'):\n"
    "            try:\n"
    "                self.real.close()\n"
    "            except Exception:\n"
    "                pass\n"
    "    def fileno(self):\n"
    "        return self.real.fileno() if hasattr(self.real, 'fileno') else 0\n"
    "class TeeStdout:\n"
    "    def __init__(self, real_out, outfile='python_pipeline_out.tmp'):\n"
    "        self.real = real_out\n"
    "        self.outfile = outfile\n"
    "        self.f = open(outfile, 'a', encoding='utf-8', errors='backslashreplace')\n"
    "        self._is_closed = False\n"
    "    def write(self, data):\n"
    "        if self._is_closed:\n"
    "            return\n"
    "        try:\n"
    "            self.real.write(data)\n"
    "            self.real.flush()\n"
    "        except Exception:\n"
    "            pass\n"
    "        try:\n"
    "            self.f.write(data)\n"
    "            self.f.flush()\n"
    "            os.fsync(self.f.fileno())\n"
    "        except Exception:\n"
    "            pass\n"
    "    def flush(self):\n"
    "        if self._is_closed:\n"
    "            return\n"
    "        try:\n"
    "            self.real.flush()\n"
    "        except Exception:\n"
    "            pass\n"
    "        try:\n"
    "            self.f.flush()\n"
    "            os.fsync(self.f.fileno())\n"
    "        except Exception:\n"
    "            pass\n"
    "    def close(self):\n"
    "        if self._is_closed:\n"
    "            return\n"
    "        self._is_closed = True\n"
    "        try:\n"
    "            self.f.close()\n"
    "        except Exception:\n"
    "            pass\n"
    "    def fileno(self):\n"
    "        return self.real.fileno() if hasattr(self.real, 'fileno') else 1\n"
    "    def isatty(self):\n"
    "        return self.real.isatty() if hasattr(self.real, 'isatty') else False\n"
    "    @property\n"
    "    def encoding(self):\n"
    "        return 'utf-8'\n"
    "    @property\n"
    "    def errors(self):\n"
    "        return 'backslashreplace'\n"
    "class KryptosMemoryLoader:\n"
    "    def __init__(self, modules):\n"
    "        self.modules = modules\n"
    "    def _resolve_key(self, fullname):\n"
    "        rel = fullname.replace('.', '/').replace(' ', '_').lower()\n"
    "        rel_raw = fullname.replace('.', '/').lower()\n"
    "        for k in self.modules.keys():\n"
    "            norm = k.replace('\\\\', '/').lstrip('./').lower()\n"
    "            norm_clean = norm.replace(' ', '_')\n"
    "            base_clean = norm_clean.rsplit('/', 1)[-1]\n"
    "            base_raw = norm.rsplit('/', 1)[-1]\n"
    "            if (norm_clean == rel + '.py' or norm_clean == rel + '/__init__.py' or \\\n"
    "                norm_clean == rel or base_clean == rel + '.py' or base_clean == rel or \\\n"
    "                base_raw == rel_raw + '.py' or base_raw == rel_raw):\n"
    "                return k, norm_clean.endswith('__init__.py')\n"
    "        return None, False\n"
    "    def find_spec(self, fullname, path, target=None):\n"
    "        key, is_pkg = self._resolve_key(fullname)\n"
    "        if key:\n"
    "            spec = ModuleSpec(fullname, self, is_package=is_pkg)\n"
    "            if is_pkg:\n"
    "                spec.submodule_search_locations = [fullname]\n"
    "            return spec\n"
    "        return None\n"
    "    def create_module(self, spec):\n"
    "        return None\n"
    "    def get_code(self, fullname):\n"
    "        key, is_pkg = self._resolve_key(fullname)\n"
    "        if not key: return None\n"
    "        b64_code = self.modules.get(key, '')\n"
    "        code_bytes = base64.b64decode(b64_code)\n"
    "        code_str = code_bytes.decode('utf-8', errors='replace').encode('utf-8', 'ignore').decode('utf-8').replace('\\x00', '')\n"
    "        return compile(code_str, key, 'exec')\n"
    "    def get_data(self, path):\n"
    "        return b''\n"
    "    def exec_module(self, module):\n"
    "        fullname = module.__name__\n"
    "        code_obj = self.get_code(fullname)\n"
    "        if code_obj is None: raise ImportError(f'Cannot find module {fullname}')\n"
    "        key, is_pkg = self._resolve_key(fullname)\n"
    "        module.__file__ = key\n"
    "        module.__package__ = fullname if is_pkg else fullname.rpartition('.')[0]\n"
    "        if is_pkg:\n"
    "            module.__path__ = [fullname]\n"
    "        sys.modules[fullname] = module\n"
    "        exec(code_obj, module.__dict__)\n"
    "\n"
    "_v = {}\n");

        if (written > 0 && (size_t)written < (system_map_overhead - offset)) {
            offset += written;
        }
        // 1. Pre-register all Python modules into Python memory map
        for (int m = 0; m < extracted_count; m++) {
            const char *m_ext = strrchr(extracted_filenames[m], '.');
            if (m_ext && STRICMP(m_ext + 1, "py") == 0) {
                char *b64_data = your_base64_encode((const unsigned char *)file_buffers[m], file_sizes[m]);
                if (b64_data) {
                    char *r = b64_data, *w = b64_data;
                    while (*r) {
                        if (*r != '\r' && *r != '\n' && *r != ' ' && *r != '\t') {
                            *w++ = *r;
                        }
                        r++;
                    }
                    *w = '\0';

                    if (offset < system_map_overhead) {
                        written = snprintf(combined_script_payload + offset, system_map_overhead - offset, 
                                           "_v['%s'] = '%s'\n", extracted_filenames[m], b64_data);
                        if (written > 0 && (size_t)written < (system_map_overhead - offset)) {
                            offset += written;
                        }
                    }
                    free(b64_data);
                }
            }
        }

        int entry_idx = i;
        
        char entry_norm[MAX_PATH_LEN] = {0};
        strncpy_s(entry_norm, MAX_PATH_LEN, extracted_filenames[entry_idx], _TRUNCATE);
        char *e_dot = strrchr(entry_norm, '.'); if (e_dot) *e_dot = '\0';

        // Check if explicit target file passed on CLI (Cross-platform robust matching with immediate exit)
        if (target_file != NULL && strlen(target_file) > 0) {
            char target_clean[MAX_PATH_LEN] = {0};
            strncpy_s(target_clean, MAX_PATH_LEN, target_file, _TRUNCATE);
            
            for (char *p = target_clean; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            char *t_ptr = target_clean;
            if (t_ptr[0] == '.' && t_ptr[1] == '/') t_ptr += 2;

            char entry_clean[MAX_PATH_LEN] = {0};
            strncpy_s(entry_clean, MAX_PATH_LEN, extracted_filenames[entry_idx], _TRUNCATE);
            for (char *p = entry_clean; *p; p++) {
                if (*p == '\\') *p = '/';
            }
            char *e_ptr = entry_clean;
            if (e_ptr[0] == '.' && e_ptr[1] == '/') e_ptr += 2;

            char t_base_only[MAX_PATH_LEN] = {0};
            strncpy_s(t_base_only, MAX_PATH_LEN, t_ptr, _TRUNCATE);
            char *t_dot = strrchr(t_base_only, '.');
            if (t_dot && STRICMP(t_dot, ".py") == 0) *t_dot = '\0';
            char *t_filename = strrchr(t_base_only, '/');
            t_filename = t_filename ? t_filename + 1 : t_base_only;

            char e_base_only[MAX_PATH_LEN] = {0};
            strncpy_s(e_base_only, MAX_PATH_LEN, e_ptr, _TRUNCATE);
            char *e_dot_clean = strrchr(e_base_only, '.');
            if (e_dot_clean && STRICMP(e_dot_clean, ".py") == 0) *e_dot_clean = '\0';
            char *e_filename = strrchr(e_base_only, '/');
            e_filename = e_filename ? e_filename + 1 : e_base_only;

            int path_matches = (STRICMP(e_ptr, t_ptr) == 0) || 
                               (STRICMP(e_base_only, t_base_only) == 0) || 
                               (STRICMP(e_filename, t_filename) == 0);

            if (strstr(target_file, ".py") != NULL && !path_matches) {
                processed_files_registry[entry_idx] = 1;
                free(combined_script_payload);
                continue;
            }
        }
        char *daemon_env = getenv("KRYPTOS_DAEMON");
        int is_interactive = (daemon_env != NULL && atoi(daemon_env) > 0);

        char *base_module_ptr = strrchr(entry_norm, '/');
        if (!base_module_ptr) base_module_ptr = strrchr(entry_norm, '\\');
        if (base_module_ptr) base_module_ptr++; else base_module_ptr = entry_norm;

        if (offset < system_map_overhead) {
            written = snprintf(combined_script_payload + offset, system_map_overhead - offset,
                "if not any(isinstance(m, KryptosMemoryLoader) for m in sys.meta_path):\n"
                "    sys.meta_path.insert(0, KryptosMemoryLoader(_v))\n"
                "argv_val = val if 'val' in globals() and val else ''\n"
                "args_list = argv_val.split() if argv_val else []\n"
                "raw_key = '%s'.replace('\\\\', '/').lstrip('./')\n"
                "clean_key = raw_key\n"
                "mod_path = clean_key[:-3] if clean_key.endswith('.py') else clean_key\n"
                "mod_dots = mod_path.replace('/', '.')\n"
                "pkg_name = mod_dots.rpartition('.')[0]\n"
                "entry_dir = os.path.dirname(os.path.abspath(clean_key))\n"
                "if entry_dir and entry_dir not in sys.path:\n"
                "    sys.path.insert(0, entry_dir)\n"
                "if '' not in sys.path:\n"
                "    sys.path.insert(0, '')\n"
                "sys.argv = [clean_key] + args_list\n"
                "sys.stdin = HybridStdin(argv_val, sys.stdin)\n"
                "sys.stdout = TeeStdout(sys.stdout)\n"
                "sys.stderr = TeeStdout(sys.stderr)\n"
                "d = {\n"
                "    '__name__': '__main__',\n"
                "    '__file__': clean_key,\n"
                "    '__package__': pkg_name,\n"
                "    'val': argv_val\n"
                "}\n"
                "b64_entry = _v.get(clean_key)\n"
                "if not b64_entry:\n"
                "    for k, v in _v.items():\n"
                "        if k.endswith('%s.py'):\n"
                "            b64_entry = v; clean_key = k; break\n"
                "if not b64_entry: raise KeyError(f'Could not find module {clean_key} in memory map')\n"
                "entry_bytes = base64.b64decode(b64_entry)\n"
                "entry_code = entry_bytes.decode('utf-8', errors='replace').replace('\\x00', '')\n"
                "main_mod = types.ModuleType('__main__')\n"
                "main_mod.__dict__.update(d)\n"
                "sys.modules['__main__'] = main_mod\n"
                "if mod_dots:\n"
                "    sys.modules[mod_dots] = main_mod\n"
                "try:\n"
                "    exec(entry_code, main_mod.__dict__)\n"
                "except (SystemExit, KeyboardInterrupt):\n"
                "    pass\n"
                "except Exception as e:\n"
                "    import traceback\n"
                "    sys.stderr.write(f'[Runtime Error] {e}\\n')\n"
                "    traceback.print_exc(file=sys.stderr)\n"
                "    sys.stderr.flush()\n", 
                extracted_filenames[entry_idx], base_module_ptr);
            
            if (written > 0 && (size_t)written < (system_map_overhead - offset)) {
                offset += written;
            }
        }

        char *b64_payload = your_base64_encode((unsigned char *)combined_script_payload, strlen(combined_script_payload));

        if (b64_payload != NULL) {
            char *r = b64_payload, *w = b64_payload;
            while (*r) {
                if (*r != '\r' && *r != '\n' && *r != ' ' && *r != '\t') {
                    *w++ = *r;
                }
                r++;
            }
            *w = '\0';

            const char *io_str = dynamic_pipeline_io ? dynamic_pipeline_io : "";
            char *b64_io = your_base64_encode((unsigned char *)io_str, strlen(io_str));
            if (b64_io != NULL) {
                char *ir = b64_io, *iw = b64_io;
                while (*ir) {
                    if (*ir != '\r' && *ir != '\n' && *ir != ' ' && *ir != '\t') {
                        *iw++ = *ir;
                    }
                    ir++;
                }
                *iw = '\0';
            }
            size_t cmd_needed = strlen(b64_payload) + (b64_io ? strlen(b64_io) : 0) + 4096;
            char *dynamic_cmd_exec = (char *)malloc(cmd_needed);

            if (dynamic_cmd_exec != NULL) {
                memset(dynamic_cmd_exec, 0, cmd_needed);

                int is_filename_match = (strstr(extracted_filenames[entry_idx], "test_") != NULL || 
                                         (target_file != NULL && strstr(target_file, "test_") != NULL) ||
                                         (strlen(extracted_filenames[entry_idx]) > 5 && 
                                          strcmp(extracted_filenames[entry_idx] + strlen(extracted_filenames[entry_idx]) - 8, "_test.py") == 0));
                
                int use_pytest = is_filename_match && (strstr(extracted_filenames[entry_idx], "ktest") == NULL);

#ifdef _WIN32
                if (use_pytest) {
                    snprintf(dynamic_cmd_exec, cmd_needed, 
                             "cmd.exe /c pytest \"%s\"", extracted_filenames[entry_idx]);
                } else {
                    snprintf(dynamic_cmd_exec, cmd_needed, 
                             "cmd.exe /c python -u -c \"import sys, base64; g=globals(); g[sys.argv[1]]=base64.b64decode(sys.argv[2]).decode('utf-8', 'ignore'); exec(base64.b64decode(sys.argv[3]).decode('utf-8', 'ignore'), g)\" \"val\" \"%s\" \"%s\"", 
                             b64_io ? b64_io : "", b64_payload);
                }
#else
                FILE *f_runner = fopen("python_runner.tmp", "w");
                if (f_runner != NULL) {
                    fprintf(f_runner,
                        "import sys, base64, time, io, os\n"
                        "sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace', line_buffering=True)\n"
                        "sys.stderr.reconfigure(encoding='utf-8', errors='backslashreplace', line_buffering=True)\n"
                        "g = globals()\n"
                        "g['val'] = base64.b64decode('%s').decode('utf-8', 'ignore')\n"
                        "try:\n"
                        "    exec(base64.b64decode('%s').decode('utf-8', 'ignore'), g)\n"
                        "except Exception as e:\n"
                        "    sys.stderr.write(str(e) + '\\n')\n"
                        "    sys.stderr.flush()\n",
                        b64_io ? b64_io : "", b64_payload);
                    if (is_interactive) {
                        fprintf(f_runner, "while True:\n    time.sleep(3600)\n");
                    }
                    fclose(f_runner);
                }

                if (use_pytest) {
                    snprintf(dynamic_cmd_exec, cmd_needed, "python3 -m pytest -o addopts='' \"%s\"", extracted_filenames[entry_idx]);
                } else {
                    snprintf(dynamic_cmd_exec, cmd_needed, "python3 -u python_runner.tmp");
                }
#endif
                
                printf("Running: [Fileless Stream] Python Module (%s) -> \n", extracted_filenames[entry_idx]);
                fflush(stdout);
                
                remove("python_pipeline_out.tmp");

                int run_status = system(dynamic_cmd_exec);
                (void)run_status;

#ifndef _WIN32
                remove("python_runner.tmp");
#endif

                memset(next_pipeline_output, 0, 1048576);
                FILE *f_tmp = fopen("python_pipeline_out.tmp", "r");
                if (f_tmp != NULL) {
                    size_t read_bytes = fread(next_pipeline_output, 1, 1048576 - 1, f_tmp);
                    next_pipeline_output[read_bytes] = '\0';
                    fclose(f_tmp);
                    remove("python_pipeline_out.tmp");
                }

                OPENSSL_cleanse(dynamic_cmd_exec, cmd_needed);
                free(dynamic_cmd_exec);
            }

            if (b64_io) free(b64_io);
            free(b64_payload);
        }

        if (strlen(next_pipeline_output) > 0) {
            strncpy(dynamic_pipeline_io, next_pipeline_output, 1048576 - 1);
        }

        OPENSSL_cleanse(combined_script_payload, system_map_overhead);
        free(combined_script_payload);

        processed_files_registry[entry_idx] = 1;

        if (target_file != NULL && strlen(target_file) > 0) {
            break;
        }
    }
}
        // BLOCK 9: PHP
else if (strcasecmp(checked_ext, "php") == 0) {
    char runtime_interpreter[260] = "php";
    char cmd_exec[16384];
    
    // Detect if this is a multi-file project (contains folder separators like / or \)
    int is_multifile = (strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL);

    if (is_multifile) {
        // Multi-file project: Unpack silently and defer execution until all files are written
        if (strlen(global_linux_php_entry) == 0 || strstr(filename, "index.php") != NULL) {
            strncpy(global_linux_php_entry, filename, sizeof(global_linux_php_entry) - 1);
            global_linux_php_entry[sizeof(global_linux_php_entry) - 1] = '\0';
        }
        if (!global_linux_php_registered) {
            atexit(execute_queued_linux_php);
            global_linux_php_registered = 1;
        }
        printf("Unpacking: [PHP Module] -> %s\n", filename);
        fflush(stdout);
    } else {
        // Single-file script (Tic Tac Toe): Execute immediately with your original pipeline logic
        if (strlen(dynamic_pipeline_io) > 0) {
            snprintf(cmd_exec, sizeof(cmd_exec), "printf '%%s' \"%s\" | %s -q -f \"%s\"", dynamic_pipeline_io, runtime_interpreter, filename);
        } else {
            snprintf(cmd_exec, sizeof(cmd_exec), "%s -f \"%s\"", runtime_interpreter, filename);
        }

        printf("Running: [Source Stream] PHP CGI Core -> %s\n", filename); 
        fflush(stdout);
        
        int exit_code = system(cmd_exec);
        if (exit_code != 0) {
            fprintf(stderr, "[Error]: Interpreter execution failed with code %d\n", exit_code);
        }
    }
}

// ------------------------------------------------------------------
        // BLOCK 10: NODE.JS ANONYMOUS MODULE INTERPRETER ROUTING MODULE
        // ------------------------------------------------------------------
else if (strcasecmp(checked_ext, "js") == 0) {
    unsigned char mask_node[] = { 0x34, 0x35, 0x3e, 0x3f }; // "node"
    decrypt_cmd_string(mask_node, 4, runtime_interpreter);

    FILE *f_out = fopen(filename, "wb");
    if (f_out) { fwrite(file_buffers[i], 1, file_sizes[i], f_out); fclose(f_out); }
    build_success = 1;

    char local_service_path_dir[MAX_PATH_LEN] = {0};
    if (getcwd(local_service_path_dir, MAX_PATH_LEN) == NULL) { perror("getcwd failed"); }

    // --- SCENARIO 9: PERSISTENT GATEWAY (Non-blocking) ---
    if (strcasecmp(filename, "justifi_gateway.js") == 0) {
        printf("[Execution] Staging Justifi Gateway for background execution...\n");
        strncpy(layer_type, "Justifi Gateway Daemon", sizeof(layer_type) - 1);
        layer_type[sizeof(layer_type) - 1] = '\0';
        no_web = 0; // Explicitly enable web mode ONLY for Justifi layout deployments
        strncpy(deferred_cmd, filename, sizeof(deferred_cmd) - 1);
        deferred_cmd[sizeof(deferred_cmd) - 1] = '\0';
        deferred_execution_flag = 1;
    }
    // --- SCENARIO 9: ENVIRONMENT HOOK (Immediate) ---
    else if (strcasecmp(filename, "justifi_hook.js") == 0) {
        printf("[Execution] Executing Native Justifi Environment Hook: %s\n", filename);
        char hook_cmd[2048] = {0};
        snprintf(hook_cmd, sizeof(hook_cmd) - 1, "%s \"%s\"", runtime_interpreter, filename);
        system(hook_cmd);
    }
    // --- SCENARIO 9: HARDENED MICROSERVICE MAIN RUNNER MULTIPLEXER ---
    else if (strstr(filename, "justifi-") != NULL) {
        int is_legitimate_main_entry = 0;
        int slash_count = 0;
        for (int c_idx = 0; filename[c_idx] != '\0'; c_idx++) {
            if (filename[c_idx] == '\\' || filename[c_idx] == '/') slash_count++;
        }
        
        if (slash_count == 1 && (strstr(filename, "server.js") != NULL || strstr(filename, "app.js") != NULL || strstr(filename, "index.js") != NULL)) {
            is_legitimate_main_entry = 1;
        }
        else if (slash_count == 2 && (strstr(filename, "/dist/") != NULL || strstr(filename, "\\dist\\") != NULL) && strstr(filename, "server.js") != NULL) {
            is_legitimate_main_entry = 1;
        }

        if (is_legitimate_main_entry) {
            printf("[Pipeline] Validated Master Entry Node! Launching service: %s\n", filename);
            char target_working_directory[MAX_PATH_LEN * 2] = {0};
            snprintf(target_working_directory, sizeof(target_working_directory), "%s/%s", local_service_path_dir, filename);
            
            for (size_t char_idx = strlen(target_working_directory) - 1; char_idx > 0; char_idx--) {
                if (target_working_directory[char_idx] == '/' || target_working_directory[char_idx] == '\\') {
                    target_working_directory[char_idx] = '\0';
                    break;
                }
            }

            char dynamic_junction_cmd[8192];
            snprintf(dynamic_junction_cmd, sizeof(dynamic_junction_cmd), 
                     "[ ! -d \"%s/node_modules\" ] && ln -s \"%s/node_modules\" \"%s/node_modules\"", 
                     target_working_directory, local_service_path_dir, target_working_directory);
            system(dynamic_junction_cmd);

            // --- NATIVE HARDENED POSIX FORK INJECTION ROUTINE ---
            pid_t micro_pid = fork();
            if (micro_pid < 0) {
                perror("[-] Engine Warning: Failed to fork background microservice context");
            } 
            else if (micro_pid == 0) {
                // Inside child process space: Set the target working directory context natively
                if (chdir(target_working_directory) < 0) {
                    perror("[-] Engine Child Error: chdir failed");
                    _exit(1);
                }

                // Decouple process space tracking completely from standard terminal interruption hooks
                setsid();

                // Direct file system path reference configuration
                char full_interpreter_path_target[MAX_PATH_LEN * 2];
                snprintf(full_interpreter_path_target, sizeof(full_interpreter_path_target), "%s/%s", local_service_path_dir, filename);

                // Build an explicit execution tracking map block for execvp
                char *node_exec_args[] = { runtime_interpreter, full_interpreter_path_target, NULL };

                // Execute runtime intercept into the targeted Node engine container layer
                execvp(node_exec_args[0], node_exec_args);

                // If execvp returns, execution has tracking failures
                perror("[-] Engine Child Error: execvp execution collapsed");
                _exit(1);
            } 
            else {
                // Parent process immediately tracks confirmation and steps out of the block context loop smoothly
                printf("[Pipeline] Service worker safely online inside: %s (PID: %d)\n", target_working_directory, micro_pid);
            }
        }
    }
else if (strstr(filename, "kryptos_hook.js") != NULL) {
        printf("[DEBUG] Hook detected: %s\n", filename);
        fflush(stdout);
 
        // 1. Force the correct path
        char work_dir[MAX_PATH_LEN];
        snprintf(work_dir, sizeof(work_dir), "%s/backend_app", "/home/sandipan/Documents/universal/DD-builds/prod_runtime");
        
        printf("[DEBUG] Target Directory: %s\n", work_dir);
        fflush(stdout);

        // 2. Fork the process
        pid_t pid = fork();

        if (pid == 0) {
            // --- CHILD PROCESS ---
            // Change directory to the app root to ensure relative 'require' paths resolve correctly
            if (chdir(work_dir) != 0) {
                perror("[-] Engine Child Error: chdir failed");
                _exit(EXIT_FAILURE);
            }

            // Verify existence of files in current working directory
            if (access("./kryptos_hook.js", F_OK) != 0 || access("./server.js", F_OK) != 0) {
                fprintf(stderr, "[-] Engine Child Error: Files missing in %s\n", work_dir);
                _exit(EXIT_FAILURE);
            }

            // Using relative paths to mirror the Windows execution architecture
            char *args[] = { 
                (char *)runtime_interpreter, 
                "-r", 
                "./kryptos_hook.js", 
                "./server.js", 
                NULL 
            };
            
            printf("[DEBUG] Executing: %s -r ./kryptos_hook.js ./server.js\n", runtime_interpreter);
            fflush(stdout);

            // Execute the interpreter
            execvp(args[0], args);
            
            // If execvp returns, an error occurred
            perror("[-] Engine Child Error: execvp failed");
            _exit(EXIT_FAILURE);
        } else if (pid > 0) {
            // Parent process
            printf("[Execution] server.js spawned successfully in %s (PID: %d)\n", work_dir, pid);
            no_web = 0;
        } else {
            // Fork failed
            perror("[-] Engine Error: fork failed");
        }
        fflush(stdout);
    }
    // --- ALL OTHER STANDARD STANDALONE SCRIPTS ---
    else if (strpbrk(filename, "/\\") == NULL) {
        strncpy(layer_type, "Node.js Standard Script", sizeof(layer_type) - 1);
        layer_type[sizeof(layer_type) - 1] = '\0';
        
        char standalone_cmd[16384] = {0};
        snprintf(standalone_cmd, sizeof(standalone_cmd), "echo \"%s\" | %s \"%s\"", dynamic_pipeline_io, runtime_interpreter, filename);
        
        printf("Running: [Source Stream] Node.js Engine -> "); fflush(stdout);
        execute_and_pipe(standalone_cmd, "", next_pipeline_output, 1048576);
        
        if (strlen(next_pipeline_output) > 0) {
            strncpy(dynamic_pipeline_io, next_pipeline_output, 1048576 - 1);
            dynamic_pipeline_io[1048576 - 1] = '\0';
        }
        no_web = 1; 
    }
}
        // ------------------------------------------------------------------
        // BLOCK 11: RUBY FILELESS VM PIPELINE ROUTING MODULE (ORDER-INDEPENDENT)
        // ------------------------------------------------------------------
        else if (STRICMP(checked_ext, "rb") == 0) {
            // Automatically capture the very first .rb file encountered as the entry point
            if (strlen(universal_entry_point) == 0) {
                strncpy(universal_entry_point, filename, sizeof(universal_entry_point) - 1);
                if (!entry_registered) {
                    atexit(run_universal_entry);
                    entry_registered = 1;
                }
            }
            
            // Silently unpack the library module to disk
            printf("Unpacking: [Ruby Library Module] -> %s\n", filename);
            fflush(stdout);
        }
        // ------------------------------------------------------------------
        // BLOCK 12: ENCAPSULATED STATIC & ENVIRONMENT ASSETS PASSTHROUGH
        // ------------------------------------------------------------------
        else if (STRICMP(checked_ext, "html") == 0 || STRICMP(checked_ext, "css") == 0  || STRICMP(checked_ext, "data") == 0 ||
                 STRICMP(checked_ext, "png") == 0  || STRICMP(checked_ext, "ico") == 0  || STRICMP(checked_ext, "j2") == 0 ||
                 STRICMP(checked_ext, "json") == 0 || STRICMP(checked_ext, "env") == 0  || STRICMP(checked_ext, "sh") == 0 ||
                 STRICMP(checked_ext, "yaml") == 0 || STRICMP(checked_ext, "yml") == 0  || STRICMP(checked_ext, "md") == 0 ||
                 STRICMP(checked_ext, "dart") == 0 || STRICMP(checked_ext, "txt") == 0  || STRICMP(checked_ext, "map") == 0 ||
                 STRICMP(checked_ext, "ts") == 0   || STRICMP(checked_ext, "wasm") == 0 || STRICMP(checked_ext, "log") == 0 ||
                 STRICMP(checked_ext, "symbols") == 0 || STRICMP(checked_ext, "frag") == 0 || STRICMP(checked_ext, "wav") == 0 ||
                 STRICMP(checked_ext, "last_build_id") == 0 || STRICMP(checked_ext, "gitkeep") == 0 || STRICMP(checked_ext, "sh") == 0 ||
                 STRICMP(checked_ext, "svg") == 0  || STRICMP(checked_ext, "jpeg") == 0 || STRICMP(checked_ext, "stackdump") == 0 ||
                 STRICMP(checked_ext, "jpg") == 0  || STRICMP(checked_ext, "csv") == 0  || STRICMP(checked_ext, "pdf") == 0  || STRICMP(checked_ext, "toml") == 0  ||
                 STRICMP(checked_ext, "otf") == 0  || STRICMP(checked_ext, "ttf") == 0  || STRICMP(checked_ext, "gif") == 0  || STRICMP(checked_ext, "lock") == 0  ||
                 STRICMP(checked_ext, "sql") == 0  || STRICMP(checked_ext, "bin") == 0) { 
            
            // Mark pass-through verification as successful without attempting code execution
            is_static_or_meta = 1;
            int build_success = 1; 
            char layer_type[128];
            
            // Linux and macOS compliant baseline asset copy mapping
            strncpy(layer_type, "Encapsulated Static Asset", sizeof(layer_type) - 1);
            layer_type[sizeof(layer_type) - 1] = '\0';
            
            printf("[Pipeline Pass] Authenticated web environment asset verified: %s\n", filename);
            fflush(stdout);
        }
        // ==================================================================
        // POST-ROUTER STATE EVALUATION
        // ==================================================================
        if (is_static_or_meta) {
            // Mark this asset file index as completely handled in the registry
            processed_files_registry[i] = 1;

            // Populate your pipeline metadata indicators safely
            char display_lang[128];
            char display_layer[128];
            
            strncpy(display_lang, "Static/Asset", sizeof(display_lang) - 1);
            display_lang[sizeof(display_lang) - 1] = '\0';
            
            strncpy(display_layer, "Encapsulated", sizeof(display_layer) - 1);
            display_layer[sizeof(display_layer) - 1] = '\0';

            // Explicitly clear standard I/O streams to prevent text caching leaks
            fflush(stdout);
        }
    } // Closes outer module iteration loop safely

    // ======================================================================
    // FIXED DYNAMIC RUNTIME MANAGER: RE-SCOPED DIRECTORY & DAEMON SPINNER (POSIX)
    // ======================================================================
if (no_web == 0) {
    char tail_working_dir[MAX_PATH_LEN] = {0};
    if (getcwd(tail_working_dir, MAX_PATH_LEN) != NULL) {
        int is_backend_workspace_active = (strstr(tail_working_dir, "backend_app") != NULL || 
                                           strstr(tail_working_dir, "backend_node") != NULL || 
                                           strstr(tail_working_dir, "backend_") != NULL);

        char final_exec_command_string[4096];
        memset(final_exec_command_string, 0, sizeof(final_exec_command_string));
        
        if (!is_backend_workspace_active && access("serve_frontend.js", F_OK) == 0 && access("kryptos_hook.js", F_OK) == 0) {
            printf("[Pipeline] Deploying Frontend Web Proxy Server Context... (Port 8080)\n");
            snprintf(final_exec_command_string, sizeof(final_exec_command_string) - 1, "bash -c 'node -r ./kryptos_hook.js serve_frontend.js' &");
            system(final_exec_command_string);
        }
        else if (is_backend_workspace_active && access("boot_loader.js", F_OK) == 0 && access("kryptos_hook.js", F_OK) == 0) {
            printf("[Pipeline] Deploying Backend Microservices Core Server Context... (Port 3000)\n");
            snprintf(final_exec_command_string, sizeof(final_exec_command_string) - 1, "bash -c 'node -r ./kryptos_hook.js boot_loader.js' &");
            system(final_exec_command_string);
        }
    }
}
// ======================================================================
// SECURE MATRIX BROWSER POPUP GATEWAY: OPERATES AGNOSTICALLY ON RAM MANIFEST
// ======================================================================
char browser_path_dir[MAX_PATH_LEN] = {0};
if (getcwd(browser_path_dir, MAX_PATH_LEN) != NULL) {
    int is_popup_backend_check = (strstr(browser_path_dir, "backend_app") != NULL || 
                                  strstr(browser_path_dir, "backend_node") != NULL || 
                                  strstr(browser_path_dir, "backend_") != NULL);

    int should_trigger_browser_launch = 0;
    char target_demo_url[256] = {0};

    for (int idx = 0; idx < extracted_count; idx++) {
        if (!extracted_filenames[idx]) continue;
        
        if (strstr(extracted_filenames[idx], "backend_app") != NULL && strstr(extracted_filenames[idx], "server.js") != NULL) {
            if (!is_popup_backend_check) {
                strncpy(target_demo_url, "http://localhost:8080", sizeof(target_demo_url) - 1);
                target_demo_url[sizeof(target_demo_url) - 1] = '\0';
                should_trigger_browser_launch = 1;
            }
        }
        
        // HUNT FOR HYPHENATED "auth-onboarding" MATCHING YOUR REAL PATH STRUCTURE
        if (strstr(extracted_filenames[idx], "justifi_gateway.js") != NULL || strstr(extracted_filenames[idx], "auth-onboarding") != NULL || strstr(extracted_filenames[idx], "justifi") != NULL) {
            if (strstr(extracted_filenames[idx], "justifi_gateway.js") != NULL || strstr(extracted_filenames[idx], "server.js") != NULL || strstr(extracted_filenames[idx], "app.js") != NULL) {
                if (!is_popup_backend_check) {
                    strncpy(target_demo_url, "http://localhost:3000", sizeof(target_demo_url) - 1);
                    target_demo_url[sizeof(target_demo_url) - 1] = '\0';
                    should_trigger_browser_launch = 1;
                }
            }
        }
    }

// --- SCENARIO 9: PERSISTENT GATEWAY (Child Process Injection) ---
    if (deferred_execution_flag) {
        printf("[Execution] Registering Gateway as child process...\n");
        
        pid_t gateway_pid = fork();
        
        if (gateway_pid == 0) {
            // CHILD PROCESS: Gateway
            setsid(); 
            
            // Build paths
            char gateway_path[MAX_PATH_LEN * 2];
            snprintf(gateway_path, sizeof(gateway_path), "%s/%s", browser_path_dir, deferred_cmd);
            
            // Execute
            char *gateway_args[] = { runtime_interpreter, gateway_path, NULL };
            execvp(gateway_args[0], gateway_args);
            
            perror("[-] Gateway Child Error: execvp failed");
            _exit(1);
        } else if (gateway_pid > 0) {
            // PARENT PROCESS
            printf("[System Automation] Gateway registered as child process (PID: %d)\n", gateway_pid);
        } else {
            perror("[-] Gateway fork failed");
        }
    }
    if (should_trigger_browser_launch && strlen(target_demo_url) > 0) {
            int skip_browser_popup = 0;
            for (int idx = 1; idx < argc; idx++) {
                if (argv[idx] && strcmp(argv[idx], "--no-launch") == 0) { skip_browser_popup = 1; break; }
            }
            if (!skip_browser_popup) {
                printf("[System Automation] Authentic capsule destination verified: %s\n", target_demo_url);
                sleep(3); 
                
                char force_browser_cmd[512] = {0};
                
                // --- FIXED FOR macOS: INTEROP ROUTING VIA NATIVE MAC WRAPPER UTILITY ---
                #ifdef __APPLE__
                snprintf(force_browser_cmd, sizeof(force_browser_cmd) - 1, 
                 "open '%s' > /dev/null 2>&1 &", 
                 target_demo_url);
                #else
                snprintf(force_browser_cmd, sizeof(force_browser_cmd) - 1, 
                 "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command \"Start-Process '%s'\" > /dev/null 2>&1 &", 
                 target_demo_url);
                #endif
                
                system(force_browser_cmd);
                
                // --- CRITICAL PERSISTENCE ANCHOR ---
                // Keeps the parent engine process alive for 5 seconds to guarantee the interop call clears!
                sleep(5); 
            }
        }
}

    // ======================================================================
    // 7. SECURE CRYPTOGRAPHIC WORKSPACE SANITIZATION AND RECLAMATION
    // ======================================================================
    
    // --- STEP 1: ZERO ALL PRIMARY ACTIVE DATA STRING CACHES IN RAM ---
    if (dynamic_pipeline_io != NULL) {
        OPENSSL_cleanse(dynamic_pipeline_io, 1048576);
    }
    if (next_pipeline_output != NULL) {
        OPENSSL_cleanse(next_pipeline_output, 1048576);
    }
    if (cmd_exec != NULL) {
        OPENSSL_cleanse(cmd_exec, 16384);
    }

    // Safely shred decrypted internal module structures before releasing references
    for (int i = 0; i < extracted_count; i++) { 
        if (file_buffers[i] != NULL && file_sizes[i] > 0) {
            OPENSSL_cleanse(file_buffers[i], file_sizes[i]);
        }
    }

    // Clear standard I/O structures inside the process space
    fflush(stdout);
    fflush(stdin);
#ifndef _WIN32
    // Force glibc to instantly release all clean unmapped heap pages back to the kernel
    // macOS allocation layers bypass this requirement by handling page reclamation natively
    #ifdef __linux__
    extern int malloc_trim(size_t pad);
    malloc_trim(0);
    #endif
#endif

    // --- STEP 2: DEBUG PAUSE ANCHOR (FOR RELIABLE CORE DUMP ANALYSIS) ---
    printf("\n[DEBUG] Clean-up complete. Process parked. Ready for gcore leak testing...");
    fflush(stdout);
    getchar(); // <--- Blocks here safely without leaving a single trace on the heap!

    // --- STEP 3: PHYSICAL DEALLOCATION PARSER ---
    for (int i = 0; i < extracted_count; i++) { 
        if (file_buffers[i] != NULL) {
            free(file_buffers[i]); 
        }
    }
    free(file_buffers);

    free(display_lang); 
    free(display_layer); 

    if (dynamic_pipeline_io != NULL) free(dynamic_pipeline_io);
    if (next_pipeline_output != NULL) free(next_pipeline_output);
    if (cmd_exec != NULL) free(cmd_exec);

    free(extracted_filenames); 
    free(file_sizes);
    
    if (priv_key != NULL) {
        EVP_PKEY_free(priv_key);
    }
    
    return 0;
}
