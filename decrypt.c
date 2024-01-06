/**
  This is the main component for the decrypt program. 
  It contains the main function and uses the other components to read the input file, 
  to perform AES decryption and to write out the plaintext output.
  @author dtcao2 Daniel Cao
  @file decrypt.c
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
  The main will perform the decryption process
  It will call readBinary and writeBinary to write the keys to a file read 
  Before writing it will use the key and cipher to create a plaintext
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
  // FILE cypherFile = argv[2];
  // FILE plainFile = argv[3];

  //byte *key = (byte *) malloc( * sizeof(byte));
  int lengthK;
  byte *key = readBinaryFile(argv[IDX_KEY], &lengthK);

  int lengthC;
  byte *cypher = readBinaryFile(argv[IDX_INPUT], &lengthC);

  //int keyLength = lengthK / BYTE_BLOCK;
  int cypherLength = lengthC / BYTE_BLOCK;

  int index = 0;
  for (int i = 0; i < cypherLength; i++){
    decryptBlock(&cypher[index], key);
    index += BLOCK_SIZE;
  }

  writeBinaryFile(argv[IDX_OUTPUT], cypher, lengthC);
  free(cypher);
  free(key);
  return 0;
}