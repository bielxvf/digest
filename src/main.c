#define REF_IMPLEMENTATION
#include "ref.h"

#define SHA512_IMPLEMENTATION
#include "sha512.h"

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

int main(int argc, char **argv)
{
  /* TODO: get rid of malloc! */

  uint8_t *data = NULL;
  uint64_t data_length;
  unsigned short j;
  uint64_t i;
  uint64_t hash[8];
  FILE **fds;

  fds = malloc((sizeof *fds) * (argc + 1));

  if (argc == 1) {
    fds[0] = stdin;
    fds[1] = NULL;
  } else {
    if (!strcmp("-h", argv[1])) {
      printf("Usage: sha512 [FILE...]\n");
      printf("With no arguments, sha512 will read from stdin.\n");
      printf("Examples:\n");
      printf("  sha512 message.txt\n");
      printf("  echo -n abc | sha512\n");
      return 0;
    }
    for (i = 0; i < argc - 1; i++) {
      fds[i] = fopen(argv[i + 1], "r");
      if (fds[i] == NULL) {
        fprintf(stderr, "Error: %s.\n", strerror(errno));
        return errno;
      }
    }
    fds[argc - 1] = NULL;
  }

  for (i = 0; fds[i] != NULL; i++) {
    data_length = read_entire_file(fds[i], &data);
    if (data_length == 0) {
      fprintf(stderr, "Error: %s.\n", strerror(errno));
      return errno;
    }
    fclose(fds[i]);

    sha512_digest(data, data_length, hash);
    free(data);
    data = NULL;

    for (j = 0; j < 8; j++) {
      printf("%016lx", hash[j]);
    }
    if (argc != 1) printf(" %s", argv[i + 1]);
    printf("\n");
  }

  free(fds);
  return 0;
}
