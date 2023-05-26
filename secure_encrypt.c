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

#include "c_crypto.h"

#define IV_SIZE 16
#define MAX 1000000
#define BUFF_SIZE 100


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
    char err[MAX_ERROR_MESSAGE_LENGTH];

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

void ipfs_add_command_save_result()
{
    char buff[BUFF_SIZE];
    FILE *fp, *fout_0;
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s 파일이 존재합니다.\n", file_name);
    }
    else
    {
        fp = popen("ipfs add enc.txt", "r");
    }
    if (NULL == fp)
    {
            perror("popen() 실패");
    }
    while (fgets(buff, BUFF_SIZE, fp))
        printf("%s\n", buff);
    int a, b = 0;
    for (int i=0; i<BUFF_SIZE;i++)
    {
        if (a==0 &(buff[i] == 0x20))
            {
                a = i+1;
            }
        else if (a!=0 & (buff[i] == 0x20))
            {
                b = i-1;
                break;
            }
    }
    unsigned char *buffer = NULL;
    buffer = malloc(sizeof(char)* (b-a));
    memcpy(buffer,buff+a,b-a+1);    
    printf("Hash value: %s\n", buffer);
    // Hash value save
    fout_0 = fopen("/Users/yeongbin/Desktop/project/IPFS-with-SST/hash_result.txt", "w");
    fwrite(buffer, 1, b-a+1, fout_0);
    printf("Save the file for hash value");
    pclose(fp);
    fclose(fout_0);
}

int main ()
{
    FILE *fin, *fout, *fenc;

    unsigned char Byte_keys[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned int cipher_key_size = 16;
    fin = fopen("/Users/yeongbin/Desktop/project/IPFS-with-SST/plain_text.txt","r");
    unsigned char *file_buf = NULL;
    unsigned long bufsize ;
    if (fin != NULL) {

        if (fseek(fin, 0L, SEEK_END) == 0) {
            bufsize = ftell(fin);
            file_buf = malloc(sizeof(char) * (bufsize + 1));

            // 이 내용이 없으면 제대로 동작하지 않음!!!
            if (fseek(fin, 0L, SEEK_SET) != 0) { /* Error */ }

            size_t newLen = fread(file_buf, sizeof(char), bufsize, fin);
            if ( ferror( fin ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                file_buf[newLen++] = '\0'; 
            }
        }
    }
    // bufsize = file_load(fin, file_buf);
    fclose(fin);
    printf("hello\n");
    printf("File size: %ld\n", bufsize);
    unsigned char iv[IV_SIZE];
    unsigned char prov_info[] = "yeongbin";
    int prov_info_len = sizeof(prov_info);
    printf("%d %d,\n",prov_info_len, IV_SIZE);
    unsigned int encrypted_length = (((bufsize) / IV_SIZE) + 1) * IV_SIZE;
    unsigned char *encrypted = (unsigned char *)malloc(encrypted_length);
    generate_nonce(IV_SIZE, iv);
    printf("IV:");
    print_buf(iv, 16);
    printf("File buffer:");
    print_buf(file_buf,10);

    //// encrypt ////
    AES_CBC_128_encrypt(file_buf, bufsize, Byte_keys, cipher_key_size, iv,
                        IV_SIZE, encrypted, &encrypted_length);
    printf("Encrypted length: %ld\n", encrypted_length);
    printf("Enc_value:");
    print_buf(encrypted, 10);
    
    //// encrypt save ////
    char *file_name = "enc.txt";
    if (0 == access(file_name,F_OK))
    {
        printf("%s 파일이 존재합니다.\n", file_name);
        exit();
    }
    else
    {
        fenc = fopen("enc.txt", "w");
    }
    unsigned char * enc_save = (unsigned char *) malloc(encrypted_length+1+IV_SIZE+1+prov_info_len);
    enc_save[0] = prov_info_len;
    memcpy(enc_save+1,prov_info,prov_info_len);
    enc_save[prov_info_len+1] = IV_SIZE;
    memcpy(enc_save+1+prov_info_len+1,iv,IV_SIZE);
    memcpy(enc_save+1+prov_info_len+1+IV_SIZE,encrypted,encrypted_length);
    printf("Total Length: %d\n",encrypted_length+1+IV_SIZE+1+prov_info_len);
    fwrite(enc_save, 1, encrypted_length+1+IV_SIZE+1+prov_info_len, fenc);
    fclose(fenc);
    ipfs_add_command_save_result();

    //// decrypt ////
    unsigned int ret_length = (encrypted_length + IV_SIZE) / IV_SIZE * IV_SIZE;
    unsigned char *ret = (unsigned char *)malloc(encrypted_length);
    AES_CBC_128_decrypt(encrypted, encrypted_length, Byte_keys, cipher_key_size, iv,
                        IV_SIZE, ret, &ret_length);
    printf("Encrypted length: %ld\n", ret_length);
    
    printf("Dec_value:");
    print_buf(ret, 10);

    fout = fopen("/Users/yeongbin/Desktop/project/IPFS-with-SST/result.txt", "w");
    fwrite(ret, 1,ret_length, fout);
    free(ret);
    fclose(fout);
    return 0;
}