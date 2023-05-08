#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define BUFF_SIZE 100

int main ()
{
    // FILE *fp;
    // int ret = system("ipfs add add.txt");
    // printf("ret : %d \n", ret);
    // return 0;
    // fp = popen("ls", "r");
    char  buff[BUFF_SIZE];
    FILE *fp, *fout;

    fp = popen("ipfs add add.txt", "r");
    if (NULL == fp)
    {
            perror("popen() 실패");
            return -1;
    }

    while (fgets(buff, BUFF_SIZE, fp))
        printf("%s\n", buff);
    int a, b = 0;
    for (int i=0; i<BUFF_SIZE;i++)
    {
        // printf("%d %x \n", i,buff[i]);
        if (a==0 &(buff[i] == 0x20))
            {
                // printf("! %x! ", buff[i]);
                a = i+1;
            }
        else if (a!=0 & (buff[i] == 0x20))
            {
                // printf("! %x !", buff[i]);
                b = i-1;
                break;
            }

    }
    printf("a %d b %d : %x %x\n",a,b, buff[a], buff[b]);
    // a~b 까지 저장

    unsigned char *buffer = NULL;
    buffer = malloc(sizeof(char)* (b-a));
    memcpy(buffer,buff+a,b-a+1);    
    printf("%s\n", buffer);
    // Hash value save
    fout = fopen("/home/ipfs-3/Desktop/sst/time.txt", "w");
    fwrite(buffer, 1, b-a, fout);
    pclose(fp);
    fclose(fout);
    return 0;


}