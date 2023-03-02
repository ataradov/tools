// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

#ifndef _GEN_H_
#define _GEN_H_

/*- Includes ----------------------------------------------------------------*/
#include <stdio.h>

/*- Types -------------------------------------------------------------------*/
typedef struct
{
  bool     generate_defines;
  bool     generate_bitfields;
  bool     generate_comments;
  bool     generate_assertions;
  bool     use_prepend_to_name;
  bool     filter_core_peripherals;
} GenOptions;

/*- Prototypes --------------------------------------------------------------*/
void gen_header_file(FILE *file, SvdFile *svd, GenOptions *opt);

#endif // _GEN_H_

