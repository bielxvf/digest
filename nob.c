#define NOB_IMPLEMENTATION

#include "nob.h"

#define BUILD_FOLDER "build/"
#define SRC_FOLDER   "src/"
#define TEST_FOLDER  "test/"
#define INCLUDE_FOLDER "include/"

#define CC "gcc"
#define WARNS "-pedantic", "-Wall", "-Wextra"
#define STD "-std=c99"

#define PROJECT_NAME "sha-512"

int main(int argc, char **argv)
{
  NOB_GO_REBUILD_URSELF(argc, argv);


  /* TODO: take subcommand, add building tests */

  if (strcmp("build", argv[1]) == 0) {
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
  } else if (strcmp("test", argv[1]) == 0) {
    if (!nob_mkdir_if_not_exists(BUILD_FOLDER)) return 1;
    Nob_Cmd cmd = {0};

    /* TODO: For every file in TEST_FOLDER */
    nob_cmd_append(
      &cmd,
      CC, 
      STD,
      WARNS,
      "-I" INCLUDE_FOLDER,
      "-o", BUILD_FOLDER "test_BitStream_append_bit", 
      TEST_FOLDER "test_BitStream_append_bit.c"
    );
    if (!nob_cmd_run_sync(cmd)) return 1;

    /* TODO: For every file in BUILD_FOLDER that starts with test_ */
    cmd.count = 0;
    nob_cmd_append(
      &cmd,
      BUILD_FOLDER "test_BitStream_append_bit"
    );
    printf("Running test_BitStream_append_bit...");
    if (!nob_cmd_run_sync(cmd)) return 1;
    printf("  PASSED\n");
  } else {
    assert(false);
  }
}
