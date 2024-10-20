#include "crypto.h"
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h> 
#include "stats.h"


long long get_elapsed_time(struct timespec start, struct timespec end) {
    long long elapsed_time = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    return elapsed_time;
}

long long dec_aux(char *filename, int is_text_file, unsigned char *key, unsigned char *iv, const EVP_CIPHER *evp_cipher) {

    unsigned char *file_content;
    size_t file_size;
    // 1 kb text file
    read_file(filename, &file_content, &file_size, is_text_file);
    unsigned char cipher_text[file_size+AES_BLOCK_SIZE];
    int cipher_len = encrypt(evp_cipher, file_content, file_size, key, iv, cipher_text);


    unsigned char plaintext[cipher_len-AES_BLOCK_SIZE];
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);    
    int ciphertext_len = decrypt(evp_cipher, cipher_text, cipher_len, key, iv, plaintext);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_time = get_elapsed_time(start, end);


    // printf("ciphertext is : \n");
    // BIO_dump_fp(stdout, (const char*) ciphertext, ciphertext_len);
    // printf("size of cipher text is : %d\n", ciphertext_len);
    // printf("time taken by the algorithm: %lld nanoseconds\n", elapsed_time);

    return elapsed_time;
}

void dec_auxN(int N, const EVP_CIPHER *evp_cipher, char *file_name, int is_text_file, unsigned char *key, unsigned char *iv, double *result) {
    long long elapsed_time;
    int i;
    double sum;
    sum = 0;

    for(i = 0; i < N; i++) {
        elapsed_time = dec_aux(file_name, is_text_file, key, iv, evp_cipher);
        sum += elapsed_time;
    }

    result[0] = sum/N;   
}


long long enc_aux(char *filename, int is_text_file, unsigned char *key, unsigned char *iv, const EVP_CIPHER *evp_cipher) {
    unsigned char *file_content;
    size_t file_size;
    // 1 kb text file
    read_file(filename, &file_content, &file_size, is_text_file);
    unsigned char ciphertext[file_size+AES_BLOCK_SIZE];
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);    
    int ciphertext_len = encrypt(evp_cipher, file_content, file_size, key, iv, ciphertext);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_time = get_elapsed_time(start, end);


    // printf("ciphertext is : \n");
    // BIO_dump_fp(stdout, (const char*) ciphertext, ciphertext_len);
    // printf("size of cipher text is : %d\n", ciphertext_len);
    // printf("time taken by the algorithm: %lld nanoseconds\n", elapsed_time);

    return elapsed_time;

}




void enc_auxN(int N, const EVP_CIPHER *evp_cipher, char *file_name, int is_text_file, unsigned char *key, unsigned char *iv, double *result) {
    long long elapsed_time;
    int i;
    double sum;
    sum = 0;

    for(i = 0; i < N; i++) {
        elapsed_time = enc_aux(file_name, is_text_file, key, iv, evp_cipher);
        sum += elapsed_time;
    }

    result[0] = sum/N;
}


int main() {

    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];

    generate_key_and_iv(key, iv);
    double en_t1[3];


    char *file_name_1KB;
    file_name_1KB = "./files/kb_1.txt";

    char *file_name_10KB;
    file_name_10KB = "./files/kb_10.txt";

    char *file_name_1MB;
    file_name_1MB = "./files/mb_1.bin";

    char *file_name_2MB;
    file_name_2MB = "./files/mb_2.bin";

    char *file_name_3MB;
    file_name_3MB = "./files/mb_3.bin";

    int N;
    N = 200;

    // ENCRYPTION
    // AES-128-CBC
    printf("\nENCRYPTIONS\n\n");
    printf("\nAES-128-CBC\n\n");

    enc_auxN(N, EVP_aes_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::AES-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aes_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::AES-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);
   
    enc_auxN(N, EVP_aes_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::AES-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aes_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::AES-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aes_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::AES-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);


    // ARIA-128-CBC
    printf("\nARIA-128-CBC\n\n");

    enc_auxN(N, EVP_aria_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::ARIA-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aria_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::ARIA-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);
   
    enc_auxN(N, EVP_aria_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::ARIA-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aria_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::ARIA-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_aria_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::ARIA-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);


    // CAMELLIA-128-CBC
    printf("\nCAMELLIA-128-CBC\n\n");

    enc_auxN(N, EVP_camellia_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::CAMELLIA-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_camellia_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("ENCRYPTION::CAMELLIA-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);
   
    enc_auxN(N, EVP_camellia_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::CAMELLIA-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_camellia_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::CAMELLIA-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    enc_auxN(N, EVP_camellia_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("ENCRYPTION::CAMELLIA-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);


    // DECRYPTION
    printf("\nDECRYPTIONS\n\n");
    printf("AES-128-CBC\n\n");

    dec_auxN(N, EVP_aes_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("DECRYPTION::AES-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aes_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("DECRYPTION::AES-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aes_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("DECRYPTION::AES-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aes_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("DECRYPTION::AES-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aes_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("DECRYPTION::AES-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);

    printf("\nARIA-128-CBC\n\n");

    dec_auxN(N, EVP_aria_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("DECRYPTION::ARIA-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aria_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("DECRYPTION::ARIA-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aria_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("DECRYPTION::ARIA-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aria_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("DECRYPTION::ARIA-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_aria_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("DECRYPTION::ARIA-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);

    printf("\nCAMELLIA-128-CBC\n\n");

    dec_auxN(N, EVP_camellia_128_cbc(), file_name_1KB, 1, key, iv, en_t1);
    printf("DECRYPTION::CAMELLIA-128-CBC::1KB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_camellia_128_cbc(), file_name_10KB, 1, key, iv, en_t1);
    printf("DECRYPTION::CAMELLIA-128-CBC::10KB | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_camellia_128_cbc(), file_name_1MB, 0, key, iv, en_t1);
    printf("DECRYPTION::CAMELLIA-128-CBC::1MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_camellia_128_cbc(), file_name_2MB, 0, key, iv, en_t1);
    printf("DECRYPTION::CAMELLIA-128-CBC::2MB  | Mean Time : %.2f ns \n", en_t1[0]);

    dec_auxN(N, EVP_camellia_128_cbc(), file_name_3MB, 0, key, iv, en_t1);
    printf("DECRYPTION::CAMELLIA-128-CBC::3MB  | Mean Time : %.2f ns \n", en_t1[0]);


    return 0;
}