#define NOB_IMPLEMENTATION

#include "nob.h"

#define BUILD_FOLDER "build/"
#define SRC_FOLDER   "src/"

#define CC "gcc"
#define WARNS "-pedantic", "-Wall", "-Wextra"
#define OPTS "-std=c89"
#define OPTS_DEBUG "-std=c89", "-g", "-no-pie", "-fsanitize=address"

#define EXECUTABLE_NAME "digest"

int main(int argc, char **argv)
{
  NOB_GO_REBUILD_URSELF(argc, argv);
  Nob_Cmd cmd = {0};

  if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;
  nob_cmd_append(
    &cmd,
    CC, 
    OPTS,
    WARNS,
    "-o", BUILD_FOLDER EXECUTABLE_NAME, 
    SRC_FOLDER"main.c"
  );
  if (!nob_cmd_run_sync_and_reset(&cmd)) return 1;

  return 0;
}
