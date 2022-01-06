#include "oracle.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Read a ciphertext from a file, send it to the server, and get back a result.
// If you run this using the challenge ciphertext (which was generated correctly),
// you should get back a 1. If you modify bytes of the challenge ciphertext, you
// may get a different result...

// Note that this code assumes a 3-block ciphertext.

int main(int argc, char *argv[]) {
  unsigned char ctext[48]; // allocate space for 48 bytes, i.e., 3 blocks
  int i, tmp, ret;
  FILE *fpIn;

  if (argc != 2) {
    printf("Usage: sample <filename>\n");
    return -1;
  }

  fpIn = fopen(argv[1], "r");

  for(i=0; i<48; i++) {
    fscanf(fpIn, "%02x", &tmp);
    ctext[i] = tmp;
  }

  fclose(fpIn);

  Oracle_Connect(); /* Note: this only needs to be called
		       ** once **, at the beginning of your program;
		       you can then use Oracle_Send as many times
		       as you like, and end by calling Oracle_Disconnect once */

  ret = Oracle_Send(ctext, 3); // the first argument is an unsigned char array ctext;
                               // the second argument indicates how many blocks ctext has
  printf("Oracle returned: %d\n", ret);

  Oracle_Disconnect();
}
