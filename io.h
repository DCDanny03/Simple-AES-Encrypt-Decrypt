/**
* This component is responsible for reading input files and 
* writing output files when the encrypt or decrypt program is done.
* @author dtcao2 Daniel Cao
* @file io.h
*/


#include <stdlib.h>
#include <stdio.h>
#include "field.h"


/**
  This function reads the contents of the binary file with the given name. 
  It returns a pointer to a dynamically allocated array of bytes containing the entire file contents. 
  The size parameter is an integer that's passed by reference to the function. 
  The function fills in this integer with the total size of the file (i.e., how many bytes are in the returned array).
  @param filename
  @param size must include adress when calling functon to size
*/
byte *readBinaryFile( char const *filename, int *size );

void writeBinaryFile( char const *filename, byte *data, int size );