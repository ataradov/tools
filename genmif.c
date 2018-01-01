/*
 * Copyright (c) 2017, Alex Taradov <alex@taradov.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*- Includes ----------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

/*- Definitions -------------------------------------------------------------*/
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*- Variables ---------------------------------------------------------------*/
static const struct option long_options[] =
{
  { "help",      no_argument,        0, 'h' },
  { "depth",     required_argument,  0, 'd' },
  { "width",     required_argument,  0, 'w' },
  { "fill",      required_argument,  0, 'f' },
  { "input",     required_argument,  0, 'i' },
  { "output",    required_argument,  0, 'o' },
  { 0, 0, 0, 0 }
};

static const char *short_options = "hd:w:f:i:o:";

static int g_depth = 0;
static int g_width = 0;
static uint32_t g_fill = 0;
static char *g_input = NULL;
static char *g_output = NULL;

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
static void check(bool cond, char *fmt, ...)
{
  if (!cond)
  {
    va_list args;

    va_start(args, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    exit(1);
  }
}

//-----------------------------------------------------------------------------
static void error_exit(char *fmt, ...)
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
static void perror_exit(char *text)
{
  perror(text);
  exit(1);
}

//-----------------------------------------------------------------------------
static void *buf_alloc(int size)
{
  void *buf;

  if (NULL == (buf = malloc(size)))
    error_exit("out of memory");

  return buf;
}

//-----------------------------------------------------------------------------
static void buf_free(void *buf)
{
  free(buf);
}

//-----------------------------------------------------------------------------
static int load_file(char *name, uint8_t **data)
{
  struct stat stat;
  int fd, rsize;

  fd = open(name, O_RDONLY | O_BINARY);

  if (fd < 0)
    perror_exit("open()");

  fstat(fd, &stat);

  *data = buf_alloc(stat.st_size);

  rsize = read(fd, *data, stat.st_size);

  if (rsize < 0)
    perror_exit("read()");

  check(rsize == stat.st_size, "cannot fully read file");

  close(fd);

  return rsize;
}

//-----------------------------------------------------------------------------
static void writeln(int fd, char *fmt, ...)
{
  char str[2048];
  va_list ap;
  int size, rsize;

  va_start(ap, fmt);
  vsnprintf(str, sizeof(str), fmt, ap);
  va_end(ap);

  size = strlen(str);

  rsize = write(fd, str, size);

  if (rsize < 0)
    perror_exit("write()");

  check(rsize == size, "error writing the file");
}

//-----------------------------------------------------------------------------
static void save_file(char *name, uint8_t *data, int size)
{
  int bytes = g_width / 8;
  int words = size / bytes;
  char *fmt[] = { NULL, "%08x : %02x;\n", "%08x : %04x;\n", NULL, "%08x : %08x;\n" };
  uint8_t  *byte_data = (uint8_t *)data;
  uint16_t *half_data = (uint16_t *)data;
  uint32_t *word_data = (uint32_t *)data;
  uint32_t value;
  int fd;

  fd = open(name, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, 0644);

  if (fd < 0)
    perror_exit("open()");

  writeln(fd, "DEPTH = %d;\n", g_depth);
  writeln(fd, "WIDTH = %d;\n", g_width);
  writeln(fd, "ADDRESS_RADIX = HEX;\n");
  writeln(fd, "DATA_RADIX = HEX;\n");
  writeln(fd, "CONTENT\n");
  writeln(fd, "BEGIN\n");

  for (int i = 0; i < g_depth; i++)
  {
    if (i >= words)
      value = g_fill;
    else if (1 == bytes)
      value = *byte_data++;
    else if (2 == bytes)
      value = *half_data++;
    else
      value = *word_data++;

    writeln(fd, fmt[bytes], i, value);
  }

  writeln(fd, "END;\n");

  close(fd);
}

//-----------------------------------------------------------------------------
static void print_help(char *name)
{
  printf("Usage: %s [options]\n", name);
  printf("Options:\n");
  printf("  -h, --help           print this help message and exit\n");
  printf("  -d, --depth <value>  number of addresses (input is adjusted accordingly)\n");
  printf("  -w, --width <value>  number of bits of data per word (8, 16, or 32)\n");
  printf("  -f, --fill <word>    fill unused locations with the provided word\n");
  printf("  -i, --input <name>   input file name\n");
  printf("  -o, --output <name>  output file name\n");
  exit(0);
}

//-----------------------------------------------------------------------------
static void parse_command_line(int argc, char **argv)
{
  int option_index = 0;
  int c;

  while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case 'h': print_help(argv[0]); break;
      case 'd': g_depth = (int)strtoul(optarg, NULL, 0); break;
      case 'w': g_width = (int)strtoul(optarg, NULL, 0); break;
      case 'f': g_fill = (uint32_t)strtoul(optarg, NULL, 0); break;
      case 'i': g_input = optarg; break;
      case 'o': g_output = optarg; break;
      default: exit(1); break;
    }
  }

  check(optind >= argc, "malformed command line, use '-h' for more information");
}

//-----------------------------------------------------------------------------
int main(int argc, char **argv)
{
  uint8_t *data;
  int size;

  parse_command_line(argc, argv);

  check(NULL != g_input, "input file name is not specified");
  check(NULL != g_output, "output file name is not specified");
  check(g_depth > 0, "depth must be greateer than zero");
  check(8 == g_width || 16 == g_width || 32 == g_width, "width must be 8, 16, or 32");

  size = load_file(g_input, &data);

  check(size % (g_width / 8) == 0, "input file size is not a multiple of the width");

  save_file(g_output, data, size);

  buf_free(data);

  return 0;
}

