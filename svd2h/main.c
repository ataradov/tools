// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

/*- Includes ----------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include "svd.h"
#include "gen.h"

/*- Types -------------------------------------------------------------------*/
typedef struct
{
  bool     help;
  char     *input;
  char     *output;
} Options;

/*- Variables ---------------------------------------------------------------*/
static Options g_opt;
static SvdOptions g_svd_opt;
static GenOptions g_gen_opt;

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
void error_exit(char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  fprintf(stderr, "Error: ");
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);

  exit(1);
}

//-----------------------------------------------------------------------------
static char *read_file(char *name)
{
  FILE *f = fopen(name, "rb");

  if (!f)
    error_exit("cannot open %s: %s", name, strerror(errno));

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *str = os_alloc(size + 1);
  int res = fread(str, size, 1, f);
  fclose(f);

  if (res != 1)
    error_exit("cannot fully read input file");

  str[size] = 0;

  return str;
}

//-----------------------------------------------------------------------------
static void print_help(const char *name, const OsOption *options)
{
  printf("SVD to C header file converter, built " __DATE__ " " __TIME__ " \n");
  printf("Latest version at https://github.com/ataradov/tools\n\n");
  printf("Usage: %s [options]\n\n", name);
  printf("Options:\n");
  os_opt_print_help(options);
  exit(0);
}

//-----------------------------------------------------------------------------
static void parse_command_line(int argc, char *argv[])
{
  static const OsOption options[] =
  {
    { 'h', "help",   NULL,   &g_opt.help,   "print this help message and exit" },
    { 'i', "input",  "file", &g_opt.input,  "input SVD file name" },
    { 'o', "output", "file", &g_opt.output, "output header file name" },

    { 'u', "svd-skip-duplicate",  NULL,   &g_svd_opt.skip_duplicate_messages,
      "skip duplicate messages" },
    { 's', "svd-convert-seq",     NULL,   &g_svd_opt.convert_sequential_index_to_array,
      "convert sequential index into an array" },
    { 'r', "svd-ignore-reserved", NULL,   &g_svd_opt.ignore_reserved_elemnets,
      "ignore reserved element names" },
    { 'p', "svd-remove-prefix",   NULL,   &g_svd_opt.remove_group_prefix,
      "remove common prefix from the register group" },
    { 'g', "svd-infer-groups",    NULL,   &g_svd_opt.infer_register_groups,
      "infer register groups from sequential arrays" },

    { 'd', "gen-defines",         NULL,   &g_gen_opt.generate_defines,
      "output definitions for field access" },
    { 'b', "gen-bitfields",       NULL,   &g_gen_opt.generate_bitfields,
      "output bitfield structures" },
    { 'c', "gen-comments",        NULL,   &g_gen_opt.generate_comments,
      "output description comments" },
    { 'a', "gen-asserts",         NULL,   &g_gen_opt.generate_assertions,
      "output assertions (useful for debugging)" },
    { 'n', "gen-use-prepend",     NULL,   &g_gen_opt.use_prepend_to_name,
      "use prependToName as a peripheral prefix" },
    { 'f', "gen-filter-core",     NULL,   &g_gen_opt.filter_core_peripherals,
      "filter out standard core peripherals (SysTick, SCB, etc)" },

    {  0 },
  };
  int last = os_opt_parse(options, argc, argv);

  if (g_opt.help)
    print_help(argv[0], options);

  os_check(last == argc, "malformed command line, use '-h' for more information");
}

//-----------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  parse_command_line(argc, argv);

  if (!g_opt.input)
    error_exit("input file is not specified");

  if (!g_opt.output)
    error_exit("output file is not specified");

  char *svd_data = read_file(g_opt.input);

  g_svd_opt.max_cluster_depth = 8;
  g_svd_opt.max_dim_size      = 8192;
  g_svd_opt.max_message_count = 100;
  g_svd_opt.generate_layout   = true;

  SvdFile *svd = svd_parse(svd_data, &g_svd_opt);

  for (SvdMessage *msg = svd->messages; msg; msg = msg->next)
  {
    if (SvdMessageType_Warning == msg->type)
      fprintf(stderr, "Warning: %s:%s\n", g_opt.input, msg->text);
    else if (SvdMessageType_Error == msg->type)
      fprintf(stderr, "Error: %s:%s\n", g_opt.input, msg->text);
  }

  printf("SVD file parsed with %d errors and %d warnings\r\n", svd->error_count, svd->warning_count);

  if (!svd->device->valid)
    error_exit("basic device information is missing, cannot generate output");

  FILE *fout = fopen(g_opt.output, "wb");

  if (!fout)
    error_exit("cannot open %s: %s", g_opt.output, strerror(errno));

  gen_header_file(fout, svd, &g_gen_opt);

  fclose(fout);
  svd_free(svd);
  os_free(svd_data);

  return 0;
}

