#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#define AES_KEY_SIZE 16 // 128 bits, or 16 bytes
#define AES_BLOCK_SIZE 16

void handleErrors(char *msg) {
        fprintf(stderr, "%s", msg);
        ERR_print_errors_fp(stderr);
        abort();
}

int encrypt(const EVP_CIPHER *evp_cipher, unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    int success_status;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx) {
        handleErrors("Failed to initialize new EVP Context !");
    }

    success_status = EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key, iv);
    if (success_status != 1) {
        handleErrors("Failed to initialize a new encryptor");
    }

    success_status = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (success_status != 1) {
        handleErrors("Failed while encryption");
    }
    ciphertext_len = len;

    success_status = EVP_EncryptFinal_ex(ctx,ciphertext+len, &len);
    if (success_status != 1) {
        handleErrors("Failed while encryption");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(const EVP_CIPHER *evp_cipher, unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int success_status;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors("Failed to intialize a new cipher ctx in decryptor");
    }

    success_status = EVP_DecryptInit_ex(ctx, evp_cipher, NULL, key, iv);
    if (success_status != 1) {
        handleErrors("Failed to initialize EVP decryptor");
    }

    success_status = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (success_status != 1) {
        handleErrors("Failed to do decryptor update");
    }

    plaintext_len = len;

    success_status = EVP_DecryptFinal_ex(ctx, plaintext+len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void generate_key_and_iv(unsigned char* key, unsigned char *iv) {
    int success_status;

    success_status = RAND_bytes(key, AES_KEY_SIZE);
    if (!success_status) {
        handleErrors("Failed to generate a random key");
    }

    success_status = RAND_bytes(iv, AES_BLOCK_SIZE);
    if (!success_status) {
        handleErrors("Failed to generate iv");
    }
}

void read_file(const char *filename, unsigned char **buffer, size_t *length, int is_text_file) {
    FILE *file = fopen(filename, "rb"); // Always use binary mode for reading
    if (!file) {
        perror("Error opening file");
        exit(1);
    }

    fseek(file, 0, SEEK_END); // Move file pointer to the end
    *length = ftell(file);    // Get file size
    rewind(file);             // Move back to the beginning

    *buffer = (unsigned char *)malloc(*length + 1); // Allocate memory (+1 for null terminator in text)
    if (!*buffer) {
        perror("Memory error");
        fclose(file);
        exit(1);
    }

    fread(*buffer, 1, *length, file); // Read the file content into buffer

    if (is_text_file) {
        (*buffer)[*length] = '\0'; // Add null terminator if it's a text file
    }

    fclose(file);
}