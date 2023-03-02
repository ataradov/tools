// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

/*- Includes ----------------------------------------------------------------*/
#include "os_common.h"
#include "svd.h"
#include "gen.h"

/*- Definitions -------------------------------------------------------------*/
#define URL                    "https://github.com/ataradov/tools"

#define BITS_IN_BYTE           8

#define MAX_DESCR_LENGTH       64
#define MAX_PREFIX_LENGTH      512
#define MAX_PREFIX_DEPTH       32

#define ALIGN_DEF              "\x01"
#define ALIGN_BF               "\x02"
#define ALIGN_IRQ              "\x03"
#define ALIGN_PER              "\x04"
#define ALIGN_COMMENT          "\x05"
#define ALIGN_COUNT            6

/*- Types -------------------------------------------------------------------*/
typedef struct
{
  char     *tag;
  char     *name;
  char     *rev;
  char     *include;
  char     *vectors[16];
} Core;

/*- Constants ---------------------------------------------------------------*/
static const int g_align[ALIGN_COUNT] = { 0, 50, 32, 24, 32, 50 };

static const Core g_cores[] =
{
#include "cores.h"
  {0},
};

/*- Variables ---------------------------------------------------------------*/
static GenOptions *g_opt;
static FILE *g_file;

static char g_prefix[MAX_PREFIX_LENGTH];
static int g_prefix_stack[MAX_PREFIX_DEPTH];
static int g_prefix_ptr;

/*- Prototypes --------------------------------------------------------------*/
static void gen_item(SvdLayout *item, int indent, u32 address, int *reserved);

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
static bool skip_peripheral(SvdPeripheral *per)
{
  static const char *skip[] =
  {
    "SysTick", "SysTick_NS", "CoreDebug", "CoreDebug_NS", "DCB", "DCB_NS",
    "DIB", "DIB_NS", "FPU", "FPU_NS", "MPU", "MPU_NS", "SCB", "SCB_NS",
    "SCnSCB", "SCnSCB_NS", "NVIC", "NVIC_NS", "DWT", "ITM", "MTB", "TPI",
    "PMU", "SAU", "PWRMODCTL", NULL,
  };
  char *name = (per->prepend && g_opt->use_prepend_to_name) ? per->prepend : per->name;

  if (!g_opt->filter_core_peripherals)
    return false;

  for (int i = 0; skip[i]; i++)
  {
    if (0 == strcmp(name, skip[i]))
      return true;
  }

  return false;
}

//-----------------------------------------------------------------------------
static Core *find_core(char *name)
{
  for (int i = 0; g_cores[i].tag; i++)
  {
    if (0 == strcmp(g_cores[i].tag, name))
      return (Core *)&g_cores[i];
  }
  return NULL;
}

//-----------------------------------------------------------------------------
static void print(int indent, char *fmt, ...)
{
  va_list args;
  char src[1024];
  char dst[1024];
  int di = 0;

  va_start(args, fmt);
  vsnprintf(src, sizeof(src), fmt, args);
  va_end(args);

  for (int i = 0; i < (indent*2); i++)
    dst[di++] = ' ';

  for (int si = 0; src[si]; si++)
  {
    if (src[si] < ALIGN_COUNT)
    {
      while (di < g_align[(int)src[si]])
        dst[di++] = ' ';
    }
    else
    {
      dst[di++] = src[si];
    }

    if (di == (sizeof(dst)-1))
      break;
  }

  dst[di] = 0;

  fprintf(g_file, "%s\n", dst);
}

//-----------------------------------------------------------------------------
static void push_prefix(char *name)
{
  int p_len = strlen(g_prefix);
  int n_len = strlen(name);

  os_assert(name && name[0]);
  os_assert(g_prefix_ptr < MAX_PREFIX_DEPTH);
  os_assert((p_len + n_len + 3) < MAX_PREFIX_LENGTH);

  g_prefix_stack[g_prefix_ptr++] = p_len;

  if (p_len)
  {
    g_prefix[p_len] = '_';
    g_prefix[p_len+1] = 0;
  }

  strcat(g_prefix, name);
}

//-----------------------------------------------------------------------------
static void pop_prefix(void)
{
  os_assert(g_prefix_ptr > 0);
  g_prefix[g_prefix_stack[--g_prefix_ptr]] = 0;
}

//-----------------------------------------------------------------------------
static char *type_name(SvdLayout *item)
{
  static char name[MAX_PREFIX_LENGTH + 16];

  if (item->struct_name)
    return item->struct_name;

  strcpy(name, g_prefix);
  strcat(name, "_Type");

  return name;
}

//-----------------------------------------------------------------------------
static char *reg_type(SvdLayout *reg)
{
  static char str[32];
  int size = reg->size*8;
  char *access;;

  if (SvdAccess_WriteOnly == reg->access || SvdAccess_WriteOnce == reg->access)
    access = "__OM ";
  else if (SvdAccess_ReadOnly == reg->access)
    access = "__IM ";
  else
    access = "__IOM";

  snprintf(str, sizeof(str), "%s uint%d_t%s", access, size, (size < 10) ? " " : "");

  return str;
}

//-----------------------------------------------------------------------------
static char *dim_name_str(SvdLayout *item, bool bf)
{
  static char str[1024];

  if (item->dim)
  {
    if (bf)
      snprintf(str, sizeof(str), "%s_b[%d]", item->name, item->dim);
    else
      snprintf(str, sizeof(str), "%s[%d]", item->name, item->dim);
  }
  else
  {
    if (bf)
      snprintf(str, sizeof(str), "%s_b", item->name);
    else
      snprintf(str, sizeof(str), "%s", item->name);
  }

  return str;
}

//-----------------------------------------------------------------------------
static char *rw_str(int access)
{
  if (SvdAccess_WriteOnly == access || SvdAccess_WriteOnce == access)
    return "W";
  else if (SvdAccess_ReadOnly == access)
    return "R";
  else
    return "R/W";
}

//-----------------------------------------------------------------------------
static char *desc(char *text)
{
  if (!text || !g_opt->generate_comments)
    return "";

  static char buf[MAX_DESCR_LENGTH+1];
  int text_len = strlen(text);
  bool was_space = false;
  int line_end = -1;
  int len = 0;

  for (int i = 0; i < text_len; i++)
  {
    int ch = text[i];

    if (ch == '\r' || ch == '\n')
    {
      if (-1 == line_end)
        line_end = i;
      ch = ' ';
    }

    if (isspace(ch) && was_space)
      continue;

    was_space = isspace(ch);

    buf[len++] = ch;

    if (len == MAX_DESCR_LENGTH)
      break;
  }

  if (len == MAX_DESCR_LENGTH)
  {
    if (line_end >= 0)
      len = line_end;

    if (len > 3)
    {
      buf[len-3] = '.';
      buf[len-2] = '.';
      buf[len-1] = '.';
    }
  }

  buf[len] = 0;

  return buf;
}

//-----------------------------------------------------------------------------
static char *desc_comment(char *text)
{
  if (!text || !g_opt->generate_comments)
    return "";

  static char buf[MAX_DESCR_LENGTH+16];

  snprintf(buf, sizeof(buf), " // %s", desc(text));

  return buf;
}

//-----------------------------------------------------------------------------
static void gen_license_text(char *text)
{
  char buf[128];
  int ptr = 0;
  int skip = 0;

  for (int i = 0; text[i]; )
  {
    bool nl = (text[i] == '\\' && text[i+1] == 'n');

    if (nl && ((text[i+2] == '\r' && text[i+3] == '\n') || (text[i+2] == '\n' && text[i+3] == '\r')))
      skip = 4;
    else if (nl && (text[i+2] == '\n' || text[i+2] == '\r'))
      skip = 3;
    else if (nl || (text[i] == '\r' && text[i+1] == '\n') || (text[i] == '\n' && text[i+1] == '\r'))
      skip = 2;
    else if (text[i] == '\r' || text[i] == '\n')
      skip = 1;
    else
      buf[ptr++] = text[i++];

    if (skip > 0 || ptr == 120)
    {
      i += skip;
      skip = 0;

      buf[ptr] = 0;
      ptr = 0;

      print(0, "// %s", buf);
    }
  }

  if (ptr > 0)
  {
    buf[ptr] = 0;
    print(0, "// %s", buf);
  }
}

//-----------------------------------------------------------------------------
static void gen_header(SvdDevice *device)
{
  char buf[64];
  time_t now = time(0);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

  print(0, "// This file was automatically generated using svd2h on %s", buf);
  print(0, "// ("URL")");
  print(0, "");

  if (device->license_text)
    gen_license_text(device->license_text);
  else
    print(0, "// No license text is present in the source file");

  print(0, "");

  if (device->vendor)
  {
    if (device->vendor_id)
      print(0, "// Vendor: %s (%s)", device->vendor, device->vendor_id);
    else
      print(0, "// Vendor: %s", device->vendor);
  }

  if (device->name)
  {
    if (device->series)
      print(0, "// Device: %s (%s)", device->name, device->series);
    else
      print(0, "// Device: %s", device->name);
  }

  if (device->description)
  {
    print(0, "// Description: %s", desc(device->description));
  }

  print(0, "");

  print(0, "#ifndef _%s_H_", device->name);
  print(0, "#define _%s_H_", device->name);
  print(0, "");
}

//-----------------------------------------------------------------------------
static void gen_footer(SvdDevice *device)
{
  print(0, "#endif // _%s_H_", device->name);
  print(0, "");
}

//-----------------------------------------------------------------------------
static void gen_core(SvdDevice *device)
{
  Core *core = NULL;

  if (device->cpu.name)
  {
    core = find_core(device->cpu.name);

    if (!core)
      print(0, "// Core '%s' is not supported", device->cpu.name);
  }
  else
  {
    print(0, "// Core type is not specified, using generic code");
    print(0, "#define __IM  volatile const");
    print(0, "#define __OM  volatile");
    print(0, "#define __IOM volatile");
    print(0, "");
  }

  print(0, "typedef enum");
  print(0, "{");

  if (core)
  {
    print(1, "// ARM %s Interrupts", core->name);

    for (int i = 0; i < 16; i++)
    {
      if (core->vectors[i])
        print(1, "%s_IRQn"ALIGN_IRQ" = %2d,", core->vectors[i], i-16);
    }

    print(0, "");
  }

  print(1, "// Peripheral Interrupts");

  if (device->interrupts)
  {
    for (SvdInterrupt *interrupt = device->interrupts; interrupt; interrupt = interrupt->next)
      print(1, "%s_IRQn"ALIGN_IRQ" = %2d,%s", interrupt->name, interrupt->index, desc_comment(interrupt->description));
  }
  else
  {
    print(1, "Dummy_IRQn"ALIGN_IRQ" = 0,");
  }

  print(0, "} IRQn_Type;");
  print(0, "");

  print(0, "#define __ICACHE_PRESENT       "ALIGN_DEF"%du", device->cpu.icache_present);
  print(0, "#define __DCACHE_PRESENT       "ALIGN_DEF"%du", device->cpu.dcache_present);
  print(0, "#define __ITCM_PRESENT         "ALIGN_DEF"%du", device->cpu.itcm_present);
  print(0, "#define __DTCM_PRESENT         "ALIGN_DEF"%du", device->cpu.dtcm_present);
  print(0, "#define __MPU_PRESENT          "ALIGN_DEF"%du", device->cpu.mpu_present);
  print(0, "#define __FPU_PRESENT          "ALIGN_DEF"%du", device->cpu.fpu_present);
  print(0, "#define __DSP_PRESENT          "ALIGN_DEF"%du", device->cpu.dsp_present);
  print(0, "#define __VTOR_PRESENT         "ALIGN_DEF"%du", device->cpu.vtor_present);
  print(0, "#define __NVIC_PRIO_BITS       "ALIGN_DEF"%du", device->cpu.nvic_prio_bits);
  print(0, "#define __Vendor_SysTickConfig "ALIGN_DEF"%du", device->cpu.vendor_systick);
  print(0, "#define __SAUREGION_PRESENT    "ALIGN_DEF"%du", device->cpu.sau_num_regions > 0);
  print(0, "");

  if (core)
  {
    print(0, "#define __%s_REV "ALIGN_DEF"0x%04xu // r%dp%d",
        core->rev, ((device->cpu.rev_r << 8) | device->cpu.rev_p), device->cpu.rev_r, device->cpu.rev_p);
    print(0, "");
    print(0, "#include <%s>", core->include);
    print(0, "");
  }
}

//-----------------------------------------------------------------------------
static void gen_peripherals(SvdDevice *device)
{
  print(0, "// Peripheral definitions");

  for (SvdPeripheral *per = device->peripherals; per; per = per->next)
  {
    if (skip_peripheral(per))
      continue;

    print(0, "#define %s_BASE"ALIGN_PER" 0x%08xu", per->name, per->base_addr);
  }

  print(0, "");

  for (SvdPeripheral *per = device->peripherals; per; per = per->next)
  {
    if (skip_peripheral(per))
      continue;

    if (per->prepend && g_opt->use_prepend_to_name)
      push_prefix(per->prepend);
    else if (per->layout->derived)
      push_prefix(per->layout->derived);
    else
      push_prefix(per->name);

    print(0, "#define %s"ALIGN_PER" ((%s *)%s_BASE)", per->name, type_name(per->layout), per->name);
    pop_prefix();
  }

  print(0, "");
}

//-----------------------------------------------------------------------------
static void gen_values(SvdEnumValue *values, int lsb, char *prefix)
{
  if (prefix)
    push_prefix(prefix);

  for (SvdEnumValue *value = values; value; value = value->next)
    print(0, "#define %s_%s_v "ALIGN_DEF"%du", g_prefix, value->name, value->value);

  for (SvdEnumValue *value = values; value; value = value->next)
    print(0, "#define %s_%s "ALIGN_DEF"(%du << %du)%s", g_prefix, value->name, value->value, lsb, desc_comment(value->description));

  if (prefix)
    pop_prefix();
}

//-----------------------------------------------------------------------------
static void gen_field_defines(SvdLayout *reg, u32 address)
{
  if (!reg->fields || !g_opt->generate_defines)
    return;

  print(0, "//--- %s : 0x%x (%s %d) %s", g_prefix, address, rw_str(reg->access), reg->size*8, desc(reg->description));

  push_prefix(reg->name);

  for (SvdField *field = reg->fields; field; field = field->next)
  {
    os_assert(SvdFieldType_Field == field->type);

    push_prefix(field->name);

    int lsb = field->lsb;
    int msb = field->msb;
    int mask = (1 << (msb-lsb+1)) - 1;

    print(0, "#define %s_p "ALIGN_DEF"%du", g_prefix, lsb);
    print(0, "#define %s_m "ALIGN_DEF"(0x%xu << %du)", g_prefix, mask, lsb);
    print(0, "#define %s_v(x) "ALIGN_DEF"(((x) >> %du) & 0x%xu)", g_prefix, lsb, mask);

    if (lsb == msb)
      print(0, "#define %s "ALIGN_DEF"(0x1u << %du)%s", g_prefix, lsb, desc_comment(field->description));
    else
      print(0, "#define %s(x) "ALIGN_DEF"(((x) & 0x%xu) << %du)%s", g_prefix, mask, lsb, desc_comment(field->description));

    if (field->r_values)
      gen_values(field->r_values->values, lsb, (field->r_values == field->w_values) ? NULL : "R");

    if (field->w_values && (field->r_values != field->w_values))
      gen_values(field->w_values->values, lsb, "W");

    print(0, "");

    pop_prefix();
  }

  pop_prefix();
}

//-----------------------------------------------------------------------------
static void gen_defines(SvdLayout *layout, u32 address)
{
  for (SvdLayout *it = layout->items; it; it = it->next)
  {
    if (SvdLayoutType_Register == it->type)
      gen_field_defines(it, address + it->offset);
    else if (SvdLayoutType_Union == it->type || SvdLayoutType_Struct == it->type)
      gen_defines(it, address + it->offset);
  }
}

//-----------------------------------------------------------------------------
static void gen_register(SvdLayout *reg, int indent, u32 address)
{
  os_assert(SvdLayoutType_Register == reg->type);

  if (!g_opt->generate_bitfields)
  {
    print(indent, "%s %s; "ALIGN_COMMENT"// [0x%x] %s", reg_type(reg), dim_name_str(reg, false), address, desc(reg->description));
    return;
  }
  else if (!reg->fields)
  {
    print(indent, "%s %s; // [0x%x] %s", reg_type(reg), dim_name_str(reg, false), address, desc(reg->description));
    return;
  }

  int size_bits = reg->size * BITS_IN_BYTE;
  int offset = 0;

  print(indent, "union {");
  print(indent+1, "%s %s; // [0x%x] %s", reg_type(reg), dim_name_str(reg, false), address, desc(reg->description));
  print(indent+1, "struct {");

  for (SvdField *field = reg->fields; field; field = field->next)
  {
    os_assert(SvdFieldType_Field == field->type);

    int lsb = field->lsb;
    int msb = field->msb;

    if (lsb > offset)
      print(indent+2, "__IM  uint%d_t "ALIGN_BF": %d;", size_bits, lsb-offset);

    if (lsb == msb)
      print(indent+2, "%s %s "ALIGN_BF": %d; // [%d] %s", reg_type(reg), field->name, field->size, lsb, desc(field->description));
    else
      print(indent+2, "%s %s "ALIGN_BF": %d; // [%d:%d] %s", reg_type(reg), field->name, field->size, msb, lsb, desc(field->description));

    offset = msb + 1;
  }

  if (offset < size_bits)
    print(indent+2, "__IM  uint%d_t "ALIGN_BF": %d;", size_bits, size_bits - offset);

  print(indent+1, "} %s;", dim_name_str(reg, true));
  print(indent, "};");
}

//-----------------------------------------------------------------------------
static void gen_struct_content(SvdLayout *layout, int indent, u32 address, int *reserved)
{
  u32 offset = 0;

  for (SvdLayout *it = layout->items; it; it = it->next)
  {
    if (it->offset > offset)
      print(indent, "__IM  uint8_t  reserved%d[%d];", (*reserved)++, it->offset - offset);

    gen_item(it, indent, address + it->offset, reserved);

    offset = it->offset + it->total_size;
  }

  if (offset < layout->size)
    print(indent, "__IM  uint8_t  reserved%d[%d];", (*reserved)++, layout->size - offset);
}

//-----------------------------------------------------------------------------
static void gen_item(SvdLayout *item, int indent, u32 address, int *reserved)
{
  if (SvdLayoutType_Register == item->type)
  {
    gen_register(item, indent, address);
  }
  else if (SvdLayoutType_Struct == item->type || SvdLayoutType_Union == item->type)
  {
    print(indent, "%s { "ALIGN_COMMENT"// [0x%x]", (SvdLayoutType_Struct == item->type) ? "struct" : "union", address);

    gen_struct_content(item, indent + 1, address, reserved);

    if (item->name)
      print(indent, "} %s;", dim_name_str(item, false));
    else
      print(indent, "};");
  }
  else if (SvdLayoutType_Cluster == item->type)
  {
    push_prefix(item->name);
    print(indent, "%s %s; "ALIGN_COMMENT"// [0x%x] %s", type_name(item), dim_name_str(item, false), address, desc(item->description));
    pop_prefix();
  }
  else
    os_assert(false);
}

//-----------------------------------------------------------------------------
static void gen_type(SvdLayout *layout, u32 address, bool gen_structs)
{
  if (gen_structs)
  {
    print(0, "typedef %s { // %s", (SvdLayoutType_Union == layout->type) ? "union" : "struct", type_name(layout));

    int reserved = 0;
    gen_struct_content(layout, 1, address, &reserved);

    print(0, "} %s; // size = %d (0x%x)", type_name(layout), layout->size, layout->size);
    print(0, "");
  }

  gen_defines(layout, address);
}

//-----------------------------------------------------------------------------
static void gen_clusters(SvdLayout *layout, u32 address, bool gen_structs)
{
  for (SvdLayout *it = layout->items; it; it = it->next)
  {
    if (SvdLayoutType_Cluster == it->type)
    {
      push_prefix(it->name);
      gen_clusters(it, address + it->offset, gen_structs);
      gen_type(it, address + it->offset, gen_structs);
      pop_prefix();
    }
    else if (SvdLayoutType_Union == it->type || SvdLayoutType_Struct == it->type)
    {
      gen_clusters(it, address + it->offset, gen_structs);
    }
  }
}

//-----------------------------------------------------------------------------
static u32 gen_register_asserts(char *type_name, char *path, SvdLayout *layout, u32 offset)
{
  u32 size = 0;

  for (SvdLayout *it = layout->items; it; it = it->next)
  {
    if (SvdLayoutType_Register == it->type)
    {
      print(0, "static_assert(offsetof(%s, %s%s) == 0x%x);", type_name, path, it->name, offset + it->offset);
      size = os_max(size, it->size);
    }
    else if (SvdLayoutType_Cluster == it->type)
    {
      print(0, "static_assert(offsetof(%s, %s%s) == 0x%x);", type_name, path, it->name, offset + it->offset);
    }
    else if (SvdLayoutType_Union == it->type || SvdLayoutType_Struct == it->type)
    {
      int len = 0;

      if (it->name)
      {
        print(0, "static_assert(offsetof(%s, %s%s) == 0x%x); // 0x%x + 0x%x", type_name, path, it->name, offset + it->offset, offset, it->offset);

        len = strlen(path);
        strcat(path, it->name);

        if (it->dim)
          strcat(path, "[0].");
        else
          strcat(path, ".");
      }

      u32 sz = gen_register_asserts(type_name, path, it, offset + it->offset);
      size = os_max(size, sz);

      if (it->name)
        path[len] = 0;
    }
  }

  return size;
}

//-----------------------------------------------------------------------------
static u32 gen_type_asserts(SvdLayout *layout)
{
  static char path[MAX_PREFIX_LENGTH] = {0};
  u32 size = 0;

  for (SvdLayout *it = layout->items; it; it = it->next)
  {
    if (SvdLayoutType_Cluster == it->type)
    {
      push_prefix(it->name);
      u32 sz = gen_type_asserts(it);
      size = os_max(size, sz);

      pop_prefix();
    }
  }

  u32 sz = gen_register_asserts(type_name(layout), path, layout, 0);
  size = os_max(size, sz);

  if (size > 0)
    sz = ((layout->size + size-1) / size) * size;
  else
    sz = 0;

  print(0, "static_assert(sizeof(%s) == 0x%x);", type_name(layout), sz);
  print(0, "");

  return size;
}

//-----------------------------------------------------------------------------
void gen_header_file(FILE *file, SvdFile *svd, GenOptions *opt)
{
  SvdDevice *device = svd->device;

  g_opt  = opt;
  g_file = file;

  gen_header(device);
  gen_core(device);

  if (g_opt->generate_assertions)
  {
    print(0, "#include <assert.h>");
    print(0, "#include <stddef.h>");
    print(0, "");
  }

  for (SvdPeripheral *per = device->peripherals; per; per = per->next)
  {
    if (skip_peripheral(per))
      continue;

    print(0, "//---------------------------------------------------------------------------");
    print(0, "//- %s - %s", per->name, desc(per->description));
    print(0, "//---------------------------------------------------------------------------");

    if (per->layout->derived)
    {
      print(0, "// Derived from %s", per->layout->derived);
      print(0, "");
    }

    bool gen_structs = !per->layout->derived;
    bool prepend     = (per->prepend && g_opt->use_prepend_to_name);

    if (gen_structs || !prepend)
    {
      push_prefix(prepend ? per->prepend : per->name);
      gen_clusters(per->layout, 0, gen_structs);
      gen_type(per->layout, 0, gen_structs);

      if (g_opt->generate_assertions && gen_structs)
        gen_type_asserts(per->layout);

      pop_prefix();
    }
  }

  gen_peripherals(device);
  gen_footer(device);
}

