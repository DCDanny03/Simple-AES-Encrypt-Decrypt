/**
* This component implements support for basic arithmetic operations in an 8-bit (a byte) Galois field. 
* These operations are used internally by AES for many steps in the encryption and decryption process.
* @author dtcao2 Daniel Cao
* @file field.c
*/

#include "field.h"
#include <stdlib.h>

#define BYTE_SIZE 8
#define LEFT_MASK 0x80
#define LEFT_SHIFT 0x1b
/**
  This function performs the addition operation in the 8-bit Galois field used by AES. 
  It adds a and b and returns the result.
  @param a the first byte
  @param b the byte adding to a
*/
byte fieldAdd( byte a, byte b )
{
    return a ^ b;
}

/**
  This function performs the subtraction operation in the 8-bit Galois field used by AES. 
  It subtracts b from a and returns the result.
  @param a byte being added to
  @param b byte that is being added to a
*/
byte fieldSub( byte a, byte b )
{
    return a ^ b;
}


/**
  This function performs the multiplication operation in the 8-bit Galois field used by AES. 
  It multiplies a and b and returns the result.
  @param a the byte being multiplied
  @param b the byte that is used for multiplying
*/
byte fieldMul( byte a, byte b )
{
    byte product = 0;
    byte mask = LEFT_MASK; //Mask to get the left most bit to determine if 1 or 0
    byte leftShift = LEFT_SHIFT; //shift the final answer to be 8 bits
    
    for (int i = 0; i < BYTE_SIZE; i++){ //iterate through all 8 bits
        if ( (b & 1) != 0){ //If the first bit (LSB) checked is 1 exclusive or a
            product ^= a;
        }
        byte shift = (byte)(a & mask); //Grab the MSB of a
        a <<= 1;
        //b >>= 1;
        if (shift != 0){ //check of MSB of a is set
            a ^= leftShift;  
        }
    
         b >>= 1; //shift so we can get the next bit value for checking
    }


    //byte productByte = product; 
    return product; 

}