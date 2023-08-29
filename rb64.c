/*
    rotate-base64 by Srdjan Rajcevic
    
    - base64 implementation with optional MIME ASCII table char left rotation (rotl) useful for obfuscation
    - Can encode/decode input up to BUFFSIZE size (use std redir for files)
    - Inspired by "Practical Malware Analysis" by Michael Sikorski and Andrew Honig
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
    #include "getopt.h"
#elif __unix
    #include <unistd.h>
#endif 

#define BUFFSIZE 1024   

void usage( char*);
void encode( unsigned char *, int);
void enc_block( unsigned char *, char *, char*, int);
void decode( unsigned char *, char*, int);
void dec_block( unsigned char *, char *);
char *rotate_table( char *, int);

char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *rot_table = NULL;
unsigned char *input = NULL;
char output[BUFFSIZE];

int main( int argc, char *argv[])
{
    int rflag = 0;
    int dflag = 0;
    int r_value = 0;
    char *end;
    int c;

    while ((c = getopt(argc, argv, "dr:i:")) != -1)
        switch(c) {
            case 'd':
                dflag=1;
                break;
            case 'r':
                rflag=1;
                r_value = strtol(optarg, &end, 10);
                break;
            case 'i':
                input = optarg;
                 break;
            case '?':
                usage(argv[0]);
        }
    if (dflag) {
        if (rflag != 0)
            rot_table = rotate_table(table,r_value);
        decode(input,output,rflag);
        printf("%s\n",output);
        exit(0);
    }
    if (rflag) {
        rot_table = rotate_table(table,r_value);
    }
    if (input == NULL) {
        usage(argv[0]);
        exit(0);
    }
    else {    
        encode(input,rflag);
        printf("%s\n",output);
    }
    return 0; 
}
void encode( unsigned char *buffer, int rflag)
{
    char *b64_table;   
    if (rflag)      // are we using rotated table of standard b64?
        b64_table = rot_table;
    else b64_table = table;
    unsigned char in[3];
    int i, len = 0;
    int j = 0;
    output[0] = '\0'; 
    while(buffer[j]) {
        len = 0;
        for(i=0; i<3; i++) {
        in[i] = (unsigned char) buffer[j];
        if(buffer[j]) {
            len++; j++;
        }
        else in[i] = 0;
        }
        if( len ) {
        enc_block( in, output, b64_table, len );
        }
    }
}
void enc_block( unsigned char *in, char *b64str, char *table, int len) {
    unsigned char out[5];       // split 3 bytes into four 6-bits 
    out[0] = table[ in[0] >> 2 ];
    out[1] = table[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? table[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? table[ in[2] & 0x3f ] : '=');
    out[4] = '\0';
    strncat(b64str, out, sizeof(out));
}
void decode( unsigned char *input, char *output, int rflag)
{
    char *b64_table;   
    if (rflag)      // are we using rotated table of standard b64?
        b64_table = rot_table;
    else b64_table = table;
    int c, phase, i;
    unsigned char in[4];
    char *p;
    output[0] = '\0';
    phase = 0; i=0;
    while(input[i]) {
        c = (int) input[i];
        if(c == '=') {
        dec_block(in, output); 
        break;
        }
        p = strchr(b64_table, c);
        if(p) {
        in[phase] = p - b64_table;
        phase = (phase + 1) % 4;
        if(phase == 0) {
            dec_block(in, output);
            in[0]=in[1]=in[2]=in[3]=0;
        }
        }
        i++;
    }
}
void dec_block( unsigned char *in, char *output) {
  unsigned char out[4];
  out[0] = in[0] << 2 | in[1] >> 4;
  out[1] = in[1] << 4 | in[2] >> 2;
  out[2] = in[2] << 6 | in[3] >> 0;
  out[3] = '\0';
  strncat(output, out, sizeof(out));
}
char *rotate_table( char *table, int key)
{
    char *rotated;
    char *tmp;
    char *tmp1;
    if ((rotated = calloc (65, sizeof(char))) == NULL) {
        perror("calloc");
        exit(-1);
    }
    tmp = table + key;
    if ((tmp1 = calloc (key+1, sizeof(char))) == NULL) {
        perror("calloc");
        exit(-1);
    }  
    if (strcpy(rotated,tmp) == NULL) {
        perror("strcpy");
        exit(-1);
    }
    if (strncpy(tmp1,table,key) == NULL) {
        perror("strncpy");
        exit(-1);
    }
    if (strcat(rotated,tmp1) == NULL) {
        perror("strcat");
        exit(-1);
    }
    free(tmp1);
    return rotated;
}
void usage(char *exe)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "%s [-d] [-r VALUE] -i INPUT\n", exe);
    fprintf(stderr, "\t-d\tdecode\n");
    fprintf(stderr, "\t-r\tuse rotl shifting of ASCII table by VALUE(int) (if omitted, use standard base64 ASCII)\n");
    fprintf(stderr, "\t-i\tINPUT to encode/decode\n");
    exit(0);
}
