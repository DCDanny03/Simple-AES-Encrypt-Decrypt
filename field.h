/**
* This component implements support for basic arithmetic operations in an 8-bit (a byte) Galois field. 
* These operations are used internally by AES for many steps in the encryption and decryption process.
* @author dtcao2 Daniel Cao
* @file field.h
*/

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#define BYTE_SIZE 8
#define LEFT_MASK 0x80
#define LEFT_SHIFT 0x1b

#ifndef _FIELD_H_
#define _FIELD_H_

/** Type used for our field, an unsigned byte. */
typedef unsigned char byte;

/** Number of bits in a byte. */
#define BBITS 8

byte fieldAdd( byte a, byte b );

byte fieldSub( byte a, byte b );

byte fieldMul( byte a, byte b );

#endif
