#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>


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


int main ()
{

    FILE *fp, *fin;
    // ipfs cat $1 > read_file1
    fp = popen("ipfs cat QmZyBbC82Xp6ckjgr2rxSESEtyipE4jG3SQ83xVxjE6MAU > enc.txt", "r");
    pclose(fp);
    
    fin = fopen("/home/taekyungkim/Desktop/IPFS-with-SST/enc.txt","r");
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
    fclose(fin);
    }
    printf("hello\n");
    printf("File size: %ld\n", bufsize);

    print_buf(file_buf,1+IV_SIZE+1+10);

    return 0;


}