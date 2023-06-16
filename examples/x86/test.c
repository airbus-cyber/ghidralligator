#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define TEST_NULL(p, L) if (p == NULL) { goto L;}; while(0)

#define SZ_MAX 0x30

#define CMD_WRITE 0
#define CMD_READ 1
#define FREE_R_BUF 2
#define NULL_R_BUF 3


unsigned char conv_hex_to_int(char* pHex) {
    unsigned char ucRes = 0;
    char hBuf[3];
    
    TEST_NULL(pHex, END_C_H2I);
    
    memset(hBuf, 0, 3);
    hBuf[0] = *pHex;
    hBuf[1] = *(pHex+1);
    
    ucRes = (unsigned char)strtol(hBuf, NULL, 16);

END_C_H2I:
    return ucRes;     
}



void hexdump(const void* data, size_t size) {

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}


int main (int argc, char **argv ) {
    
    unsigned char* pReq = NULL;
    unsigned int szReq = 0;
    unsigned int szReqHex = 0;
    unsigned int i = 0;
    
    if (argc != 2) {
        exit(-1);
    }
    
    
    // Convert hex string (argv[1]) to bin
    szReqHex = strlen(argv[1]);
    if (szReqHex % 2 != 0) {
        exit(-1);
    }
    
    szReq = szReqHex / 2;
    pReq = malloc(szReq);
    TEST_NULL(pReq, END);
    memset(pReq, 0, szReq);
    
    while (i < szReq) {
        *(pReq+i) = conv_hex_to_int(argv[1]+(i*2));
        i++;
    }
    
    unsigned int offset = 0;
    unsigned char cmd;
    unsigned char* pData = NULL;
    
    pData = malloc(SZ_MAX);
    TEST_NULL(pData, END);
    unsigned char o;
    unsigned char sz;
    unsigned char* pPayload;
    
    unsigned char* pReadBuf = NULL;
    
    while (offset < szReq) {
        
        cmd = *(pReq+offset);
        offset++;
        
        
        // write overflow
        switch (cmd) {
            case CMD_WRITE:
                o = *(pReq+offset);
                offset++;
                sz = *(pReq+offset);
                offset++;
                pPayload = pReq+offset;
                offset = offset + sz;
                memcpy(pData+o, pPayload, sz);
                printf("Write of %d bytes at offset 0x%x\n", sz, o);
                break;
                
            case CMD_READ:
                // read before write
                o = *(pReq+offset);
                offset++;
                sz = *(pReq+offset);
                offset++;
                printf("Read of %d bytes at offset 0x%x\n", sz, o);
                if (pReadBuf == NULL) {
                    pReadBuf = malloc(sz);
                    // Use after free if called twice
                    TEST_NULL(pReadBuf, END);
                }
                memcpy(pReadBuf, pData+o, sz);
                hexdump(pReadBuf, sz);
                break;
            
            
            case FREE_R_BUF:
                printf("free 0x%x\n", pReadBuf);
                free(pReadBuf);
                break;
            
            
            case NULL_R_BUF:
                printf("set to null pointer\n");
                pReadBuf = NULL;
                break;
            
            
            
                
            default:   
                printf("Command unkown: 0x%x\n", cmd);
                break;
                
        }
    }    
        
    
    
    
END:
    if (pReq != NULL) {
        free(pReq);
    }
    
    if (pData != NULL) {
        free(pData);
    }
    
    exit(0);
}



