#ifndef _DLP_H_
#define _DLP_H_

// C Wrapper for DLP IBE
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


void encrypt(char *ID , void *KEY, void *CT);
void decrypt(char *ID,const int16_t *csk, void *CT, void *KEY);
void masterpublic(void *);
  
#ifdef __cplusplus
}
#endif
  
#endif
