/**
* This component is responsible for reading input files and 
* writing output files when the encrypt or decrypt program is done.
* @author dtcao2 Daniel Cao
* @file io.c
*/

//#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "io.h"



#define MAX_BYTES 16

/**
  This function reads the contents of the binary file with the given name. 
  It returns a pointer to a dynamically allocated array of bytes containing the entire file contents. 
  The size parameter is an integer that's passed by reference to the function. 
  The function fills in this integer with the total size of the file (i.e., how many bytes are in the returned array).
  @param filename the name of file
  @param size must include adress when calling functon to size
*/
byte *readBinaryFile( char const *filename, int *size )
{
    FILE *fp = fopen(filename, "rb");
    if(!fp){
        fprintf( stderr, "Can't open file: %s\n", filename ); //Errpr checking, if file cant be read or open
        exit(EXIT_FAILURE);
    }


    int len;
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    byte *buffer = (byte *) malloc(len * sizeof(byte));
    //size_t bytesRead = 0;
    fread(buffer, sizeof(byte), len, fp);   //2nd parameter is 1 because the size of char is alwaus 1 byter5

    
    

    *size = len;

    if((*size % MAX_BYTES) != 0){
        fprintf( stderr, "Bad key file: %s\n", filename ); //Errpr checking, if file cant be read or open
        exit(EXIT_FAILURE);
    }

    fclose(fp);
    return buffer;
}


/**
  This function writes the contents of the given data array (in binary) to the file with the given name. 
  The size parameter says how many bytes are contained in the data array.
  @param filename name of file
  @param data the data being written
  @param size the size of the file
*/
void writeBinaryFile( char const *filename, byte *data, int size )
{
    FILE *dest = fopen(filename, "wb");
    if(!dest){
        fprintf( stderr, "Can't open file: %s\n", filename ); //Errpr checking, if file cant be read or open
        exit(EXIT_FAILURE);
    }

    fwrite(data, sizeof(byte), size, dest);

    fclose(dest);

}