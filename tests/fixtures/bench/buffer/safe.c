#include <string.h>
#include <stdlib.h>
void load(void) {
  char buf[16];
  char *v = getenv("USER");
  strncpy(buf, v, sizeof(buf) - 1);
}
