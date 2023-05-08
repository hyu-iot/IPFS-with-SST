#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>



#define MAX 1000000

void print_buf(unsigned char *buf, size_t size) {
    char hex[size * 3 + 1];
    for(size_t i = 0; i < size; i++) {
        sprintf(hex + 3 * i, " %.2x", buf[i]);
    }
    printf(" %s\n", hex);
}

void generate_nonce(int length, unsigned char *buf) {
    int x = RAND_bytes(buf, length);
    if (x == -1) {
        printf("Failed to create Random Nonce");
        exit(1);
    }
}
void print_last_error(char *msg) {
    char err[1000000];

    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n", msg, err);
    exit(1);
}

void AES_CBC_128_encrypt(unsigned char *plaintext,
                         unsigned int plaintext_length, unsigned char *key,
                         unsigned int key_length, unsigned char *iv,
                         unsigned int iv_length, unsigned char *ret,
                         unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (!EVP_EncryptUpdate(ctx, ret, (int *)ret_length, plaintext,
                           plaintext_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptUpdate failed");
    }
    unsigned int temp_len;
    if (!EVP_EncryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_EncryptFinal_ex failed");
    }
    *ret_length += temp_len;
    EVP_CIPHER_CTX_free(ctx);
}


long int get_file_length(char *filename)
{
 long int length = 0;
 FILE *fp;
 fp = fopen(filename,"rb");
 if( fp == NULL ) return -1;
 fseek(fp,0,2);
 length = ftell(fp);
 fclose(fp);
 return length;
}

void AES_CBC_128_decrypt(unsigned char *encrypted,
                         unsigned int encrypted_length, unsigned char *key,
                         unsigned int key_length, unsigned char *iv,
                         unsigned int iv_length, unsigned char *ret,
                         unsigned int *ret_length) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (!EVP_DecryptUpdate(ctx, ret, (int *)ret_length, encrypted,
                           encrypted_length)) {
        EVP_CIPHER_CTX_free(ctx);
        print_last_error("EVP_DecryptUpdate failed");
    }
    unsigned int temp_len;
    // if (!EVP_DecryptFinal_ex(ctx, ret + *ret_length, (int *)&temp_len)) {
    //     EVP_CIPHER_CTX_free(ctx);
    //     print_last_error("EVP_DecryptFinal_ex failed");
    // }
    *ret_length += temp_len;
    EVP_CIPHER_CTX_free(ctx);
}




int main()
{
    FILE *fin, *fout;
    unsigned char Byte_keys[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned int cipher_key_size = 16;
    fin = fopen("/home/ipfs-3/Desktop/IPFS-with-SST/enc.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    
    if (fin != NULL) {
    /* Go to the end of the file. */
        if (fseek(fin, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            bufsize = ftell(fin);
            if (bufsize == -1) { /* Error */ }

            /* Allocate our buffer to that size. */
            file_buf = malloc(sizeof(char) * (bufsize + 1));

            /* Go back to the start of the file. */
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            /* Read the entire file into memory. */
            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; /* Just to be safe. */
            }
        }
    fclose(fin);
    }
    
    unsigned int iv_size = 16;
    unsigned char iv[] = {0xdb, 0xd2,0x26,0x80,0x1c,0x67,0xbf,0x8a,0x5a, 0xc8,0xac, 0xfc, 0xac, 0x79, 0x5e, 0x0f};

    unsigned int ret_length = (bufsize + iv_size) / iv_size * iv_size;
    unsigned char *ret = (unsigned char *)malloc(bufsize);
    AES_CBC_128_decrypt(file_buf, bufsize, Byte_keys, cipher_key_size, iv,
                        iv_size, ret, &ret_length);
    printf("decrypted length: %ld\n", ret_length);

    printf("dec_value:");
    print_buf(ret, 10);

    fout = fopen("/home/ipfs-3/Desktop/IPFS-with-SST/rpi_result.txt", "w");
    fwrite(ret, 1,ret_length, fout);
    free(ret);
    fclose(fout);
}