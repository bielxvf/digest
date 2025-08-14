#define NOB_IMPLEMENTATION

#include "nob.h"

#define BUILD_FOLDER "build/"
#define SRC_FOLDER   "src/"
#define TEST_FOLDER  "test/"
#define INCLUDE_FOLDER "include/"

#define CC "gcc"
#define WARNS "-pedantic", "-Wall", "-Wextra"
#define STD "-std=c89"

#define PROJECT_NAME "sha-512"

int main(int argc, char **argv)
{
  NOB_GO_REBUILD_URSELF(argc, argv);

  if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;
  Nob_Cmd cmd = {0};
  nob_cmd_append(
    &cmd,
    CC, 
    STD,
    WARNS,
    "-I" INCLUDE_FOLDER,
    "-o", BUILD_FOLDER PROJECT_NAME, 
    SRC_FOLDER"main.c"
  );
  if (!nob_cmd_run_sync(cmd)) return 1;

  return 0;
}
