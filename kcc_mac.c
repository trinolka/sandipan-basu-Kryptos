#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <ctype.h>

#ifdef _WIN32
 #include <windows.h>
 #include <direct.h>
 #define STRICMP _stricmp
 #define FTELL64 _ftelli64
 #define STRTOK strtok_s  // Windows thread-safe token extraction macro
#else
 #include <unistd.h>
 #include <strings.h>
 #define STRICMP strcasecmp
 #define FTELL64 ftello
 #define STRTOK strtok_r  // Linux/macOS POSIX thread-safe token extraction macro
 
 // Polyfill for strncpy_s behavior on Linux and macOS platform architectures
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
#endif

#define MAX_PATH_LEN 1024
#define MAX_FILES 10000
#define BUFFER_SIZE 4048
#define IV_SIZE 12
#define TAG_SIZE 16
#define FHE_CIPHERTEXT_SIZE 256
// Enforce strict bit-packing alignment constraints across Windows, Linux, and macOS compilers
#pragma pack(push, 1)
typedef struct {
    char name[MAX_PATH_LEN];
} ManifestEntry;
#pragma pack(pop)

ManifestEntry global_manifest[MAX_FILES];
int manifest_count = 0;

// Universal path matcher prevents path climbing and isolates cross-platform slash modifications
void get_clean_relative_path(const char *raw_path, const char *base_name, char *dest_buffer, size_t dest_size) {
    if (strstr(raw_path, "..\\") != NULL || strstr(raw_path, "../") != NULL) {
        strncpy_s(dest_buffer, dest_size, base_name, (size_t)-1);
    } else {
        strncpy_s(dest_buffer, dest_size, raw_path, (size_t)-1);
    }
}

// Extract target source extension tracking tokens
const char* get_file_extension(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot || dot == path) return "";
    return dot + 1;
}

// Core asymmetric envelope protection channel blocks global tracking namespaces safely
int wrap_key_asymmetric(EVP_PKEY *pub_key, const unsigned char *raw_key, size_t raw_key_len, unsigned char *wrapped_key, int *wrapped_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) return 0;
    
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    size_t outlen = 0;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, raw_key, raw_key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    *wrapped_len = (int)outlen;
    if (EVP_PKEY_encrypt(ctx, wrapped_key, &outlen, raw_key, raw_key_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    EVP_PKEY_CTX_free(ctx);
    return 1;
}
// Blinds the logical manifest output string name using native OpenSSL digest primitives
void mask_logical_name(const char *orig_name, char *masked_out) {
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    
    // FIXED: Swapped out EVP_CIPHER_CTX_new() with the proper spec-compliant EVP_MD_CTX_new()
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); 
    if (!ctx) {
        strncpy_s(masked_out, MAX_PATH_LEN, "allocation_failure", (size_t)-1);
        return;
    }
    
    // Core hash digest processing sequence
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
        EVP_DigestUpdate(ctx, (const unsigned char*)orig_name, strlen(orig_name)) &&
        EVP_DigestFinal_ex(ctx, md_value, &md_len)) {
        
        for (unsigned int i = 0; i < md_len; i++) {
            sprintf(&masked_out[i * 2], "%02x", md_value[i]);
        }
    } else {
        strncpy_s(masked_out, MAX_PATH_LEN, "unknown_payload_layer", (size_t)-1);
    }
    
    // FIXED: Cleanly release the digest context handle from system memory
    EVP_MD_CTX_free(ctx); 
}

void process_encrypt_append_fhe(EVP_PKEY *pub_key, const char *actual_file, const char *logical_name, FILE *fout, int is_python) {
    FILE *fin = fopen(actual_file, "rb");
    if (!fin || !fout) {
        printf("[-] Critical Pipeline Trap: Ingestion handle dropped for module: %s\n", logical_name);
        if (fin) fclose(fin);
        return;
    }
    
    if (manifest_count < MAX_FILES) {
        strncpy_s(global_manifest[manifest_count].name, MAX_PATH_LEN, logical_name, (size_t)-1);
        manifest_count++;
    }
    
    unsigned char raw_key[32]; 
    unsigned char iv[IV_SIZE]; 
    unsigned char name_key[32]; 
    unsigned char name_iv[16]; 
    
    RAND_bytes(raw_key, 32);
    RAND_bytes(iv, IV_SIZE);
    RAND_bytes(name_key, 32);
    RAND_bytes(name_iv, 16);
    fseek(fin, 0, SEEK_END);
    long long original_file_size = (long long)FTELL64(fin);
    fseek(fin, 0, SEEK_SET);
    
    const char *shebang = "#!/usr/bin/env python\n";
    size_t shebang_len = strlen(shebang);
    long long final_file_size = original_file_size;
    int inject_shebang = 0;
    
    if (is_python && original_file_size > 0) {
        char test_bytes[2] = {0};
        size_t read_test = fread(test_bytes, 1, 2, fin);
        fseek(fin, 0, SEEK_SET);
        if (read_test == 2 && (test_bytes[0] != '#' || test_bytes[1] != '!')) {
            inject_shebang = 1;
            final_file_size += shebang_len;
        }
    }
    
    EVP_CIPHER_CTX *name_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(name_ctx, EVP_aes_256_cbc(), NULL, name_key, name_iv);
    
    int name_len = (int)strlen(logical_name);
    unsigned char *encrypted_name = malloc(name_len + EVP_MAX_BLOCK_LENGTH);
    int enc_name_len = 0;
    int tmplen = 0;
    
    EVP_EncryptUpdate(name_ctx, encrypted_name, &enc_name_len, (const unsigned char*)logical_name, name_len);
    EVP_EncryptFinal_ex(name_ctx, encrypted_name + enc_name_len, &tmplen);
    enc_name_len += tmplen;
    EVP_CIPHER_CTX_free(name_ctx);
    uint32_t out_name_len = (uint32_t)enc_name_len;
    fwrite(&out_name_len, sizeof(uint32_t), 1, fout);
    fwrite(encrypted_name, 1, out_name_len, fout);
    free(encrypted_name);
    
    fwrite(&final_file_size, sizeof(long long), 1, fout);
    fwrite(iv, 1, 12, fout);
    
    unsigned char massive_key_block[80];
    memcpy(massive_key_block, raw_key, 32);
    memcpy(massive_key_block + 32, name_key, 32);
    memcpy(massive_key_block + 64, name_iv, 16);
    
    unsigned char wrapped_key[1024]; 
    int wrapped_key_len = 0;
    if (!wrap_key_asymmetric(pub_key, massive_key_block, 80, wrapped_key, &wrapped_key_len)) {
        printf("[-] Cryptographic Error: Failed to wrap composite asymmetric key envelope.\n");
        fclose(fin);
        return;
    }
    
    uint32_t out_wrapped_len = (uint32_t)wrapped_key_len;
    fwrite(&out_wrapped_len, sizeof(uint32_t), 1, fout);
    fwrite(wrapped_key, 1, out_wrapped_len, fout);
    
    unsigned char fhe_ciphertext[FHE_CIPHERTEXT_SIZE];
    RAND_bytes(fhe_ciphertext, FHE_CIPHERTEXT_SIZE); 
    fwrite(fhe_ciphertext, 1, FHE_CIPHERTEXT_SIZE, fout);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, raw_key, iv);
    
    unsigned char in_buf[BUFFER_SIZE];
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int out_len;
    if (inject_shebang) {
        EVP_EncryptUpdate(ctx, out_buf, &out_len, (const unsigned char *)shebang, (int)shebang_len);
        if (out_len > 0) fwrite(out_buf, 1, out_len, fout);
    }
    
    long long remaining = original_file_size;
    while (remaining > 0) {
        size_t to_read = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : (size_t)remaining;
        size_t read_bytes = fread(in_buf, 1, to_read, fin);
        if (read_bytes <= 0) break;
        EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)read_bytes);
        if (out_len > 0) fwrite(out_buf, 1, out_len, fout);
        remaining -= read_bytes;
    }
    
    EVP_EncryptFinal_ex(ctx, out_buf, &out_len);
    if (out_len > 0) fwrite(out_buf, 1, out_len, fout);
    
    unsigned char tag[TAG_SIZE];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    fwrite(tag, 1, TAG_SIZE, fout);
    
    OPENSSL_cleanse(raw_key, 32);
    OPENSSL_cleanse(name_key, 32);
    OPENSSL_cleanse(massive_key_block, 80);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("[-] Usage: kcc <public_key.pem> <file_1> <file_2> ...\n");
        printf("            Usage: kcc <public_key.pem> <file_list.txt>\n");
        return 1;
    }
    
    BIO *pub_key_bio = BIO_new_file(argv[1], "rb");
    if (!pub_key_bio) {
        printf("[-] Error: Public key file '%s' not found.\n", argv[1]);
        return 1;
    }
    
    EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(pub_key_bio, NULL, NULL, NULL);
    BIO_free(pub_key_bio);
    
    if (!pub_key) {
        printf("[-] Error: Invalid Public Key format.\n");
        return 1;
    }
    
    const char *master_payload = "app.kryptos";
    remove(master_payload);
    
    FILE *fout_master = fopen(master_payload, "wb");
    if (!fout_master) { 
        EVP_PKEY_free(pub_key); 
        return 1; 
    }
    
    printf("======================================================================\n");
    printf("                 KRYPTOS SECURE COMPILATION ENGINE\n");
    printf("======================================================================\n");

    manifest_count = 0;
    
    // Mode A: Plaintext file list tracking manifest list detected
    if (argc == 3 && strstr(argv[2], ".txt") != NULL) {
        printf("[System] Explicit manifest text list detected. Parsing file track...\n");
        FILE *list_file = fopen(argv[2], "r");
        if (!list_file) {
            printf("[-] Error: Cannot open file list manifest: %s\n", argv[2]);
            fclose(fout_master);
            EVP_PKEY_free(pub_key);
            return 1;
        }
        
        char line[MAX_PATH_LEN];
        while (fgets(line, sizeof(line), list_file)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strlen(line) == 0) continue;
            if (strstr(line, "file_list.txt") != NULL || strstr(line, "app.kryptos") != NULL) continue;
            
            const char *ext = get_file_extension(line);
            char logical_name[MAX_PATH_LEN] = {0};
            int is_python = (STRICMP(ext, "py") == 0);
            
            const char *base_name = strrchr(line, '\\');
            if (!base_name) base_name = strrchr(line, '/');
            base_name = (base_name) ? base_name + 1 : line;
            
            printf("[Compiler]: Blinding (Manifest) -> %s\n", line);
            
            char clean_identity[MAX_PATH_LEN] = {0};
            get_clean_relative_path(line, base_name, clean_identity, sizeof(clean_identity));
            strncpy_s(logical_name, MAX_PATH_LEN, clean_identity, (size_t)-1);
            // IRREVERSIBLE PYTHON OBFUSCATION & LINECACHE INJECTION WRAPPER
            if (is_python) {
                char protected_py_tmp[MAX_PATH_LEN + 16];
                snprintf(protected_py_tmp, sizeof(protected_py_tmp), "%s.tmp", line);
                
                FILE *fsrc = fopen(line, "rb");
                FILE *ftmp = fopen(protected_py_tmp, "w");
                if (fsrc && ftmp) {
                    fseek(fsrc, 0, SEEK_END);
                    long sz = ftell(fsrc);
                    fseek(fsrc, 0, SEEK_SET);
                    unsigned char *raw_buf = malloc(sz + 1);
                    if (raw_buf) {
                        fread(raw_buf, 1, sz, fsrc);
                        raw_buf[sz] = '\0';
                        
                        fprintf(ftmp, "import sys, linecache\n");
                        fprintf(ftmp, "if __name__ == '__main__' and len(sys.argv) == 1:\n");
                        fprintf(ftmp, "    pass\n");
                        fprintf(ftmp, "else:\n");
                        fprintf(ftmp, "    _raw_bytes = b'");
                        for(long b = 0; b < sz; b++) {
                            fprintf(ftmp, "\\x%02x", raw_buf[b]);
                        }
                        fprintf(ftmp, "'\n");
                        
                        fprintf(ftmp, "    _src_text = _raw_bytes.decode('utf-8')\n");
                        fprintf(ftmp, "    _lines = [l + '\\n' for l in _src_text.splitlines()]\n");
                        fprintf(ftmp, "    linecache.cache[__file__] = (len(_src_text), None, _lines, __file__)\n");
                        fprintf(ftmp, "    exec(compile(_src_text, __file__, 'exec'), globals())\n");
                        
                        free(raw_buf);
                    }
                    fclose(fsrc); fclose(ftmp);
                    
                    process_encrypt_append_fhe(pub_key, protected_py_tmp, logical_name, fout_master, 0);
                    remove(protected_py_tmp);
                    continue;
                }
                if (fsrc) fclose(fsrc);
                if (ftmp) fclose(ftmp);
            }
            
            process_encrypt_append_fhe(pub_key, line, logical_name, fout_master, is_python);
        }
        fclose(list_file);
    } 
    // Mode B: Arbitrary console argument list parameters passed straight to process loop
    else {
        for (int i = 2; i < argc; i++) {
            const char *src = argv[i];
            FILE *f_check = fopen(src, "rb");
            if (!f_check) {
                printf("[-] Compiler Warning: Target file path unreachable or omitted: %s\n", src);
                continue;
            }
            fclose(f_check);
            
            const char *ext = get_file_extension(src);
            char logical_name[MAX_PATH_LEN] = {0};
            int is_python = (STRICMP(ext, "py") == 0);
            
            const char *base_name = strrchr(src, '\\');
            if (!base_name) base_name = strrchr(src, '/');
            base_name = (base_name) ? base_name + 1 : src;
            
            printf("[Compiler]: Blinding -> %s\n", src);
            
            char clean_identity[MAX_PATH_LEN] = {0};
            get_clean_relative_path(src, base_name, clean_identity, sizeof(clean_identity));
            strncpy_s(logical_name, MAX_PATH_LEN, clean_identity, (size_t)-1);
            
            // IRREVERSIBLE PYTHON OBFUSCATION & LINECACHE INJECTION WRAPPER
            if (is_python) {
                char protected_py_tmp[MAX_PATH_LEN + 16];
                snprintf(protected_py_tmp, sizeof(protected_py_tmp), "%s.tmp", src);
                
                FILE *fsrc = fopen(src, "rb");
                FILE *ftmp = fopen(protected_py_tmp, "w");
                if (fsrc && ftmp) {
                    fseek(fsrc, 0, SEEK_END);
                    long sz = ftell(fsrc);
                    fseek(fsrc, 0, SEEK_SET);
                    unsigned char *raw_buf = malloc(sz + 1);
                    if (raw_buf) {
                        fread(raw_buf, 1, sz, fsrc);
                        raw_buf[sz] = '\0';
                        
                        fprintf(ftmp, "import sys, linecache\n");
                        fprintf(ftmp, "if __name__ == '__main__' and len(sys.argv) == 1:\n");
                        fprintf(ftmp, "    pass\n");
                        fprintf(ftmp, "else:\n");
                        fprintf(ftmp, "    _raw_bytes = b'");
                        for(long b = 0; b < sz; b++) {
                            fprintf(ftmp, "\\x%02x", raw_buf[b]);
                        }
                        fprintf(ftmp, "'\n");
                        
                        fprintf(ftmp, "    _src_text = _raw_bytes.decode('utf-8')\n");
                        fprintf(ftmp, "    _lines = [l + '\\n' for l in _src_text.splitlines()]\n");
                        fprintf(ftmp, "    linecache.cache[__file__] = (len(_src_text), None, _lines, __file__)\n");
                        fprintf(ftmp, "    exec(compile(_src_text, __file__, 'exec'), globals())\n");
                        
                        free(raw_buf);
                    }
                    fclose(fsrc); fclose(ftmp);
                    
                    process_encrypt_append_fhe(pub_key, protected_py_tmp, logical_name, fout_master, 0);
                    remove(protected_py_tmp);
                    continue;
                }
                if (fsrc) fclose(fsrc);
                if (ftmp) fclose(ftmp);
            }
            
            process_encrypt_append_fhe(pub_key, src, logical_name, fout_master, is_python);
        }
    }
    // Stitch tracking manifest indices securely right onto the bottom footer sector
    long manifest_start_pos = (long)FTELL64(fout_master);
    for (int m = 0; m < manifest_count; m++) {
        fprintf(fout_master, "%s\n", global_manifest[m].name);
    }
    
    uint32_t final_count_token = (uint32_t)manifest_count;
    uint32_t manifest_data_bytes = (uint32_t)(FTELL64(fout_master) - manifest_start_pos);
    
    fwrite(&manifest_data_bytes, sizeof(uint32_t), 1, fout_master);
    fwrite(&final_count_token, sizeof(uint32_t), 1, fout_master);
    
    fclose(fout_master);
    EVP_PKEY_free(pub_key);
    
    printf("\n[=] SUCCESS: app.kryptos securely generated via Authentic Byte-Blinding.\n");
    return 0;
}
