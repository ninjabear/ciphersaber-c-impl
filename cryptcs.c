// cryptcs.c

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

#define CRYPTCS_FILE_ERROR -1
#define CRYPTCS_NOMEMORY -2

// could have diced this up some to make some pretty subroutines but. later!
// CIPHERSABER1 (Which this code uses) IS VULNERABLE
// read cryptanalisis here
// http://ciphersaber.gurus.com/cryptanalysis.html
// I just wanted to be a cipherknight :(

#define UCHAR unsigned char

void secureErase(FILE* fpToErase)
{
    long lSiz;
    int i, j;
    fseek(fpToErase, 0, SEEK_END);
    lSiz = ftell(fpToErase);
    for (i=0; i<10; i++)
    {
        for (j=0; j<=lSiz; j++)
        {
            fputc('\0', fpToErase);
        }
        rewind(fpToErase);
    }
}

void swap(unsigned int *a, unsigned int *b)
{
    unsigned int tmp;
    tmp = *a;
    *a = *b;
    *b = tmp;
}

int cryptcs_encrypt(const char* pszCryptFN, const char* pszKeyIn)
{
    //pszInfile : filename to encrypt
    //pszKey : to encrypt data with
    FILE* fpIn;
    FILE* fpTMP;
    char szTMPFN[12];

    unsigned int state[256], i, j, n; // the state array;
    UCHAR IV[11]; // 10 byte IV & NULL
    UCHAR* pKey = (UCHAR*)malloc(strlen(pszKeyIn)+11);
        if (pKey == NULL) { return CRYPTCS_NOMEMORY; }
    UCHAR cipherbyte;

    srand(time(NULL));
    sprintf(szTMPFN, "%07d.tmp", rand());
    fpIn = fopen(pszCryptFN, "rb");

    if (fpIn != NULL)
    {
        /* temp file ! */
        fpTMP = fopen(szTMPFN, "rb");
        if (fpTMP == NULL) // double check our temp file doesn't exist!
        {
            fpTMP = fopen(szTMPFN, "wb");   // if it doesn't open it for write
            if (fpTMP == NULL) { return CRYPTCS_FILE_ERROR; } // there is a real problem opening the tmp file
        }
        else { //szTMPFN exists!
            return CRYPTCS_FILE_ERROR;
        }
        /* temp file ok and open as fpTMP. Proceed to encrypt! */

        // generate 10 byte IV
        for (i=0; i<10; i++)        // KEY BUILDING AND INITALISATION
        {
            IV[i] = (UCHAR)rand();
        }
        IV[10] = '\0';
        // add it to the key
        strcpy(pKey, pszKeyIn);
        strcat(pKey, IV);
        // initialise state array
        for (i=0; i<=255; i++)
        {
            state[i] = i;
        }
        // permute key
        j = n = 0;
        for (i=0; i<=255; ++i)
        {
            n = i % strlen(pKey);
            j = (j + state[i] + pKey[n]) % 256;
            swap(&state[i], &state[j]);
        }
        fwrite(IV, 1, strlen(IV), fpTMP); // write IV to file

        cipherbyte = getc(fpIn);
        i=j=0; // encrypt
        while (!feof(fpIn))
        {
            i = (i + 1) % 256;
            j = (j + state[i]) % 256;
            swap (&state[i], &state[j]);
            n = (state[i] + state[j]) % 256;
            fputc(state[n] ^ cipherbyte, fpTMP);
            cipherbyte = getc(fpIn);
        }
        rewind(fpIn);
        secureErase(fpIn);
        fclose(fpIn);
        fclose(fpTMP);
        remove(pszCryptFN);
        rename(szTMPFN, pszCryptFN);
    }
    else {
        return CRYPTCS_FILE_ERROR; // infile doesn't exist
    }
 free(pKey);
 return 0;
}

int cryptcs_decrypt (const char* pszCryptFN, const char* pszKeyIn)
{
    //pszInfile : filename to decrypt
    //pszKey : to decrypt data with
    FILE* fpIn;
    FILE* fpTMP;
    char szTMPFN[12];

    unsigned int state[256], i, j, n; // the state array;
    UCHAR IV[11]; // 10 byte IV & NULL
    UCHAR* pKey = (UCHAR*)malloc(strlen(pszKeyIn)+11);
        if (pKey == NULL) { return CRYPTCS_NOMEMORY; }
    UCHAR cipherbyte;

    srand(time(NULL));
    sprintf(szTMPFN, "%07d.tmp", rand());
    fpIn = fopen(pszCryptFN, "rb");

    if (fpIn != NULL)
    {
        /* temp file ! */
        fpTMP = fopen(szTMPFN, "rb");
        if (fpTMP == NULL) // double check our temp file doesn't exist!
        {
            fpTMP = fopen(szTMPFN, "wb");   // if it doesn't open it for write
            if (fpTMP == NULL) { return CRYPTCS_FILE_ERROR; } // there is a real problem opening the tmp file
        }
        else { //szTMPFN exists!
            return CRYPTCS_FILE_ERROR;
        }
        /* temp file ok and open as fpTMP. Proceed to decrypt! */

        // read 10 byte IV
        fread(IV, 1, 10, fpIn);
        IV[10] = '\0'; // make it a nice string

        // add it to the key
        strcpy(pKey, pszKeyIn);
        strcat(pKey, IV);
        // initialise state array
        for (i=0; i<=255; i++)
        {
            state[i] = i;
        }
        // permute key
        j = n = 0;
        for (i=0; i<=255; ++i)
        {
            n = i % strlen(pKey);
            j = (j + state[i] + pKey[n]) % 256;
            swap(&state[i], &state[j]);
        }

        cipherbyte = getc(fpIn); // get pointer already 10 bytes in
        i=j=0; // decrypt
        while (!feof(fpIn))
        {
            i = (i + 1) % 256;
            j = (j + state[i]) % 256;
            swap (&state[i], &state[j]);
            n = (state[i] + state[j]) % 256;
            fputc(state[n] ^ cipherbyte, fpTMP);
            cipherbyte = getc(fpIn);
        }
        rewind(fpIn);
        secureErase(fpIn);
        fclose(fpIn);
        fclose(fpTMP);
        remove(pszCryptFN);
        rename(szTMPFN, pszCryptFN);
    }
    else {
        return CRYPTCS_FILE_ERROR; // infile doesn't exist
    }
 free(pKey);
 return 0;
}
