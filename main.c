/**
 * A little tool for decrypting claymore's homegrown
 * encryption that he uses in ethminer (and some other
 * miners.) I'm not exactly sure what this cipher is called
 * but it's pretty simple. Probably not intended as a super 
 * secure means of protecting stuff, but it keeps most of the 
 * lamers out.
 *
 * Not sure if this works on more recent verions -- last time 
 * I tried it was with 9.8, you're on your own for more recent 
 * versions.
 *
 * Also, this code is pretty shitty, but I really don't want
 * to dedicate more thought to this than I already have. 
 *
 * @goobur
 */

#include <stdio.h>
#include <stdlib.h>
#include "miniz.h"

#define PERMUTE1(x)   ((x >> 4) & 0x04)    
#define PERMUTE2(x)   ((x >> 2) & 0x02)      
#define PERMUTE3(x)   ((x << 5) & 0x80)       
#define PERMUTE4(x)   ((x << 2) & 0x40)      
#define PERMUTE5(x)   ((x << 4) & 0x20)       
#define PERMUTE6(x)   ((x << 3) & 0x08)
#define PERMUTE7(x)   ((x >> 5) & 0x01)
#define PERMUTE8(x)   ((x >> 3) & 0x10)

#define BPERMUTE1(x)   ((x & 0x04) << 4)
#define BPERMUTE2(x)   ((x & 0x02) << 2)
#define BPERMUTE3(x)   ((x & 0x80) >> 5)
#define BPERMUTE4(x)   ((x & 0x40) >> 2)
#define BPERMUTE5(x)   ((x & 0x20) >> 4)
#define BPERMUTE6(x)   ((x & 0x08) >> 3)
#define BPERMUTE7(x)   ((x & 0x01) << 5)
#define BPERMUTE8(x)   ((x & 0x10) << 3)


// This is essentially the "key" for these algo
// it changes based on what you're decrypting
// for ex. the main binary data.bin uses different 
// values here, but the kernels data1a.bin etc...
// use these.
#define PRIME1   991
#define PRIME2   977
#define PRIME3   223
#define XORMASK 0x40


unsigned char shuffle_bits(unsigned char x) {
    return BPERMUTE1(x) | BPERMUTE2(x) | BPERMUTE3(x) | BPERMUTE4(x) | BPERMUTE5(x) | BPERMUTE6(x) | BPERMUTE7(x) | BPERMUTE8(x);
}
unsigned char unshuffle_bits(unsigned char x) {
    return PERMUTE1(x) | PERMUTE2(x) | PERMUTE3(x) | PERMUTE4(x) | PERMUTE5(x) | PERMUTE6(x) | PERMUTE7(x) | PERMUTE8(x);
}

char *decryptinate(const char *file, size_t *size_out){
    FILE *fp = fopen(file, "rb");
    char *buffer = NULL;
    size_t size = 0;
    if(fp == NULL) return NULL;
    
    fseek(fp, 0, 2);
    size = ftell(fp);
    fseek(fp, 0,0);
    
    buffer = (char *)malloc(size);
    
    if(buffer == NULL) return buffer;
    fread(buffer, size, 1, fp);
    
    if(size/2 > 0) {
        char *bend = &buffer[size-1];
        int i = 0;

        do
        {
            char temp = buffer[i];
            buffer[i++] = *bend;
            *bend-- = temp;
        }while(size/2 > i);
    }
    
    int iterator = 0;
    int v13 = 0, v17 = 0, v18 = 0;
    do {
        unsigned char bfromdata = buffer[iterator];
        unsigned char dshft     = unshuffle_bits(bfromdata);
        unsigned char key       = 0;
        
        v17 = v13 / PRIME1;
        v18 = v13;
        v13 += PRIME2;
        
        key = (v18 - PRIME3*v17);
        
        buffer[iterator++] = key ^ dshft ^ XORMASK;
    } while(iterator < size);
    
    if(size_out) *size_out = size;
    
    return buffer;
}


int encrypt(const char *file, unsigned char *buffer, int sizeout){
    int iterator = 0;
    int v13 = 0, v17 = 0, v18 = 0;
    do {
        unsigned char bfromdata = buffer[iterator];
        
        unsigned char key       = 0;
        v17 = v13 / PRIME1;
        v18 = v13;
        v13 += PRIME2;
        key = (v18 - PRIME3*v17);
        
        unsigned char dshft     = shuffle_bits(key ^ XORMASK ^ bfromdata);
        
        buffer[iterator++] = dshft;
    } while(iterator < sizeout);
    
    if(sizeout/2 > 0) {
        unsigned char *bend = &buffer[sizeout-1];
        int i = 0;
        
        // reverse data
        do
        {
            unsigned char temp = buffer[i];
            buffer[i++] = *bend;
            *bend-- = temp;
        }while(sizeout/2 > i);
    }
    FILE *fp = fopen(file, "wb");
    if(fp == NULL) return 0;
    
    fwrite(buffer, sizeout, 1, fp);
    fclose(fp);
    return 1;
}

void print_usage(const char * argv[]) {
    printf("General usage: \n");
    printf("%s -[d/e] [input] [output]\n", argv[0]);
}


int main(int argc, const char * argv[]) {

    if(argc < 4) {
BAIL:
        print_usage(argv);
        exit(-1);
    }

    if(!strncmp(argv[1], "-d", 2 )) {
        printf("Decrypting %s -> %s...\n", argv[2], argv[3]);
        size_t size;
        int cmp_status;
        char*buffer=NULL, *dbuffer=NULL;
        buffer = decryptinate(argv[2], &size);

        size_t d_size = 15*size;
        dbuffer = malloc(d_size);
        cmp_status = uncompress((unsigned char *)dbuffer, &d_size, (unsigned char*)buffer, size);
        if (cmp_status != Z_OK)
        {
            printf("uncompress() failed 0x%X!\n", cmp_status);
            free(dbuffer);
            free(buffer);
            exit(-1);
        }
        
        FILE *fout = fopen(argv[3], "wb");

        if(*(unsigned int *)(dbuffer) != d_size - 8) {
            printf("There's something fucky in this data, I'm going to write it anyway...\n");
        }

        fwrite(dbuffer + 8, d_size - 8, 1, fout);
        fclose(fout);

        free(buffer);
        free(dbuffer);
    }else if(!strncmp(argv[1], "-e", 2)) {
        FILE *fp = fopen(argv[2], "rb");
        unsigned char *pCmp, *pUncomp;
        size_t size = 0;
        int cmp_status;

        printf("Encrypting %s -> %s...\n", argv[2], argv[3]);

        if(fp == NULL) {
            printf("Couldn't open the input file...\n");
            exit(-1);
        }
        
        fseek(fp, 0, 2);
        size = ftell(fp) + 8; // There's 8 bytes for some dumb-ass unused header
        fseek(fp, 0, 0);
        
        size_t src_len = size;
        size_t cmp_len = compressBound(src_len);
        
        pCmp    = malloc(cmp_len);
        pUncomp = malloc(src_len);
        
        // Set the header
        *(unsigned int*)(pUncomp)     = (unsigned int) (size - 8);
        *(unsigned int*)(pUncomp + 4) = (unsigned int) 1;

        fread(pUncomp + 8, size, 1, fp);
        fclose(fp);
        
        cmp_status = compress(pCmp, &cmp_len, (const unsigned char *)pUncomp, size);
        
        printf("Original size: %lu bytes\nCompressed: %lu bytes\n", size, cmp_len);
        encrypt(argv[3], pCmp, cmp_len);

    } else {
        goto BAIL;
    }
    return 0;
}
