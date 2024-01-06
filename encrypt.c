/**
  This is the main component for the encrypt program. 
  It contains the main function and uses the other components to read the input file, 
  to perform AES encryption and to write out the ciphertext output.
  @author dtcao2 Daniel Cao
  @file encrpyt.c
*/

#include <stdio.h>
#include <stdlib.h>
#include "io.h"
#include "field.h"
#include "aes.h"

#define REQUIRED_ARGS 4
#define BYTE_BLOCK 16
#define IDX_KEY 1
#define IDX_INPUT 2
#define IDX_OUTPUT 3

/**
  The main will perform the encryption process
  It will call readBinary and writeBinary to write the keys to a file read 
  Before writing it will use the key and plaintext to create a cipher 
  Will iterate through a loop to determine the amount of 16 byte blocks in the file
  @param argc the amount of arguments
  @param argv the command arguments
*/
int main(int argc, char *argv[])
{


  if(argc != REQUIRED_ARGS ) {
    fprintf( stderr, "usage: encrypt <key-file> <input-file> <output-file>\n" );
    exit( EXIT_FAILURE );
  }

  // FILE keyFile = argv[1];
  // FILE plainFile = argv[2];
  // FILE cypherFile = argv[3];

  //byte *key = (byte *) malloc( * sizeof(byte));
  int lengthK;
  byte *key = readBinaryFile(argv[IDX_KEY], &lengthK);

  int lengthP;
  byte *plain = readBinaryFile(argv[IDX_INPUT], &lengthP);

  //int keyLength = lengthK / BYTE_BLOCK;
  int plainLength = lengthP / BYTE_BLOCK;

  int index = 0;
  for (int i = 0; i < plainLength; i++){
    encryptBlock(&plain[index], key);
    index += BLOCK_SIZE;
  }

  writeBinaryFile(argv[IDX_OUTPUT], plain, lengthP);
  free(plain);
  free(key);
  return 0;
}