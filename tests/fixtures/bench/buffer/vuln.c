#include <string.h>
#include <stdlib.h>
void load(void) {
  char buf[16];
  char *v = getenv("USER");
  strcpy(buf, v);
}
