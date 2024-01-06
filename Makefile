# The Makefile for the Encrypt and Decrypt

all: encrypt decrypt aesTest fieldTest

# Rebuild the expecutable if one of the objects changes.
# Will rebuild the encrypt
encrypt: encrypt.o io.o aes.o field.o
	gcc -Wall -std=c99 encrypt.o io.o aes.o field.o -o encrypt

# Will rebuild the decrypt
decrypt: decrypt.o io.o aes.o field.o
	gcc -Wall -std=c99 decrypt.o io.o aes.o field.o -o decrypt

aesTest: aesTest.o aes.o field.o
	gcc -Wall -std=c99 -g aesTest.o aes.o field.o -o aesTest

fieldTest: fieldTest.o field.o 
	gcc -Wall -std=c99 -g fieldTest.o field.o -o fieldTest

# Rebuild encrypt.o if there's a change in its source file or
# in the header it includes.
encrypt.o: encrypt.c io.h aes.h field.h
	gcc -g -Wall -std=c99 -g encrypt.c -c

# Rebuild decrypt.o if there's a change in its source file or
# in the header it includes.
decrypt.o: decrypt.c io.h aes.h field.h
	gcc -g -Wall -std=c99 -g decrypt.c -c

# Rebuild io.o if there's a change in its implementation
# file or its header.
io.o: io.c io.h field.h
	gcc -g -Wall -std=c99 -g io.c -c

# Rebuild aes.o if there's a change in its implementation
# file or its header.
aes.o: aes.c aes.h field.h
	gcc -Wall -std=c99 -g aes.c -c

# Rebuild field.o if there's a change in its implementation
# file or its header.
field.o: field.c field.h 
	gcc -Wall -std=c99 -g field.c -c

aesTest.o: aesTest.c aes.c aes.h field.h 
	gcc -Wall -std=c99 -g aesTest.c -c

fieldTest.o: fieldTest.c field.c field.h
	gcc -Wall -std=c99 -g fieldTest.c -c

aesTest.o: aesTest.c aes.c aes.h field.h
	gcc -Wall -std=c99 -g aesTest.c -c
clean:
	rm -f *.o encrypt decrypt