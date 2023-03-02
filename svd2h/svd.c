// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

/*- Includes ----------------------------------------------------------------*/
#include "os_common.h"
#include "svd.h"

/*- Definitions -------------------------------------------------------------*/
#define BITS_IN_BYTE           8
#define MAX_FIELD_DIM_SIZE     32

#define error(parser, loc, ...)   message(parser, SvdMessageType_Error, __LINE__, loc, __VA_ARGS__)
#define warning(parser, loc, ...) message(parser, SvdMessageType_Warning, __LINE__, loc, __VA_ARGS__)

/*- Types -------------------------------------------------------------------*/
typedef struct
{
  SvdFile  *file;
  OsArena  *arena;
  SvdOptions *opt;
  SvdDevice  *device;
  XmlFile  *xml;
  int      cluster_depth;
  SvdLayout *layouts;

  bool     error;
  int      last_index;
  int      last_type;
  int      message_count;
  int      skipped_count;
  bool     message_limit;

  int      size;
  int      access;
  int      protection;
  u32      reset_value;
  u32      reset_mask;
} SvdParser;

typedef struct
{
  char     *name;
  int      value;
} EnumPair;

/*- Constants ---------------------------------------------------------------*/
static SvdOptions svd_default_options_val =
{
  .max_cluster_depth = 8,
  .max_dim_size      = 8192,
  .max_message_count = 16,
  .skip_duplicate_messages           = true,
  .convert_sequential_index_to_array = true,
  .ignore_reserved_elemnets          = true,
  .remove_group_prefix               = true,
  .generate_layout                   = false,
  .infer_register_groups             = true,
};

/*- Prototypes --------------------------------------------------------------*/
static void parse_group(SvdParser *parser, XmlElement *element, SvdItem *group);

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
#define list_add_sorted(list, value, sort) \
  do { \
    if (list == NULL || value->sort < list->sort) \
    { \
      value->next = list; \
      list = value; \
    } \
    else \
    { \
      typeof(value) ptr; \
      for (ptr = list; ptr->next && ptr->next->sort <= value->sort; ptr = ptr->next); \
      value->next = ptr->next; \
      ptr->next = value; \
    } \
  } while (0)

//-----------------------------------------------------------------------------
#define list_dup(parser, list) \
  do { \
    typeof(list) old_list = list; \
    typeof(list) tail = NULL; \
    list = NULL; \
    for (typeof(list) old = old_list; old; old = old->next) \
    { \
      typeof(list) new = os_arena_alloc(parser->arena, sizeof(*list)); \
      *new = *old; \
      if (tail) \
        tail->next = new; \
      else \
        list = new; \
      tail = new; \
    } \
  } while (0)

//-----------------------------------------------------------------------------
static void flush_messages(SvdParser *parser)
{
  if (0 == parser->skipped_count)
    return;

  SvdMessage *msg = os_arena_alloc(parser->arena, sizeof(SvdMessage));

  msg->type  = parser->last_type;
  msg->index = parser->message_count++;
  msg->text  = os_arena_alloc(parser->arena, 64);
  snprintf(msg->text, 64, "skipped %d duplicate messages", parser->skipped_count);

  list_add_sorted(parser->file->messages, msg, index);

  parser->last_index    = 0;
  parser->skipped_count = 0;
}

//-----------------------------------------------------------------------------
static void message(SvdParser *parser, int type, int index, XmlLocation loc, char *fmt, ...)
{
  va_list args;
  char str[256];

  if (SvdMessageType_Error == type)
    parser->error = true;

  if (SvdMessageType_Error == type)
    parser->file->error_count++;
  else if (SvdMessageType_Warning == type)
    parser->file->warning_count++;
  else
    os_assert(false);

  if (parser->message_limit)
    return;

  if (parser->message_count >= parser->opt->max_message_count)
  {
    SvdMessage *msg = os_arena_alloc(parser->arena, sizeof(SvdMessage));

    msg->type  = SvdMessageType_Warning;
    msg->index = parser->message_count++;
    msg->text  = os_arena_alloc(parser->arena, 64);
    snprintf(msg->text, 64, "maximum number of messages reached (%d)", parser->opt->max_message_count);

    list_add_sorted(parser->file->messages, msg, index);

    parser->message_limit = true;

    return;
  }

  if (parser->opt->skip_duplicate_messages && index == parser->last_index)
  {
    parser->skipped_count++;
    return;
  }

  flush_messages(parser);

  va_start(args, fmt);
  vsnprintf(str, sizeof(str), fmt, args);
  va_end(args);

  SvdMessage *msg = os_arena_alloc(parser->arena, sizeof(SvdMessage));
  int size = strlen(str) + 32;

  msg->type  = type;
  msg->index = parser->message_count++;
  msg->text  = os_arena_alloc(parser->arena, size);

  if (loc.line > 0)
    snprintf(msg->text, size, "%d,%d: %s", loc.line, loc.column, str);
  else
    strcpy(msg->text, str);

  list_add_sorted(parser->file->messages, msg, index);

  parser->last_index = index;
  parser->last_type  = type;
}

//-----------------------------------------------------------------------------
static inline bool str_eq(const char *a, const char *b)
{
  return (a && b && (0 == strcmp(a, b)));
}

//-----------------------------------------------------------------------------
static inline bool str_eq_ci(const char *a, const char *b)
{
  while (a[0] && b[0])
  {
    if (tolower(a[0]) != tolower(b[0]))
      return false;
    a++;
    b++;
  }

  return true;
}

//-----------------------------------------------------------------------------
static XmlElement *find_element(XmlElement *in, const char *name)
{
  for (XmlElement *el = in->elements; el; el = el->next)
  {
    if (str_eq(el->name, name))
      return el;
  }

  return NULL;
}

//-----------------------------------------------------------------------------
static char *get_attribute_value(XmlElement *element, const char *name)
{
  for (XmlAttribute *attr = element->attributes; attr; attr = attr->next)
  {
    if (str_eq(attr->name, name))
      return attr->value;
  }

  return NULL;
}

//-----------------------------------------------------------------------------
static void missing_mandatory(SvdParser *parser, XmlElement *in, char *name)
{
  error(parser, in->name_loc, "missing mandatory element '%s'", name);
}

//-----------------------------------------------------------------------------
static bool get_bool(SvdParser *parser, XmlElement *in, char *name, bool optional, bool def)
{
  XmlElement *el = find_element(in, name);

  if (el)
  {
    if (str_eq(el->text, "true") || str_eq(el->text, "1"))
      return true;
    else if (str_eq(el->text, "false") || str_eq(el->text, "0"))
      return false;
    else
      error(parser, el->name_loc, "invalid boolean value, must be 'true' or 'false'");
  }
  else if (!optional)
    missing_mandatory(parser, in, name);

  return def;
}

//-----------------------------------------------------------------------------
static char *get_str(SvdParser *parser, XmlElement *in, char *name, bool optional, char *def)
{
  XmlElement *el = find_element(in, name);
  char *str = def;

  if (el)
  {
    char *text = el->text ? el->text : "";
    str = os_arena_alloc(parser->arena, strlen(text) + 1);
    strcpy(str, text);
  }
  else if (!optional)
    missing_mandatory(parser, in, name);

  return str;
}

//-----------------------------------------------------------------------------
static char *get_name(SvdParser *parser, XmlElement *in)
{
  char *name = get_str(parser, in, "name", false, NULL);
  static const char *reserved = "reserved";

  if (!name || !parser->opt->ignore_reserved_elemnets)
    return name;

  // Ignore 'RESERVED', 'RESERVED_', 'RESERVED{N}'
  char *str = name;

  for (int i = 0; reserved[i]; i++)
  {
    if (tolower(*str++) != reserved[i])
      return name;
  }

  strtoul(str, &str, 10);

  if (str[0] == 0 || (str[0] == '_' && str[1] == 0))
  {
    warning(parser, in->name_loc, "ignoring reserved element '%s'", name);
    parser->error = true;
    return NULL;
  }

  return name;
}

//-----------------------------------------------------------------------------
static bool snn_str_to_u64(char *str, u64 *value)
{
  int base = 10;
  u64 res;

  if (str[0] == '+')
    str++;

  if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
  {
    base = 16;
    str += 2;
  }
  else if (str[0] == '#')
  {
    base = 16;
    str += 1;
  }

  res = strtoul(str, &str, base);

  if (str[0] == 'k' || str[0] == 'K')
    res *= 0x400ull;
  else if (str[0] == 'm' || str[0] == 'M')
    res *= 0x100000ull;
  else if (str[0] == 'g' || str[0] == 'G')
    res *= 0x40000000ull;
  else if (str[0] == 't' || str[0] == 'T')
    res *= 0x10000000000ull;
  else if (str[0] != 0)
    return false;

  *value = res;

  return true;
}

//-----------------------------------------------------------------------------
static u64 get_snn(SvdParser *parser, XmlElement *in, char *name, bool optional, u64 def)
{
  XmlElement *el = find_element(in, name);

  if (el)
  {
    u64 value;

    if (el->text && snn_str_to_u64(el->text, &value))
      return value;
    else
      error(parser, el->name_loc, "expected a scaled non-negative integer value");
  }
  else if (!optional)
    missing_mandatory(parser, in, name);

  return def;
}

//-----------------------------------------------------------------------------
static int get_enum(SvdParser *parser, XmlElement *in, char *name, const EnumPair *pairs, bool optional, int def)
{
  XmlElement *el = find_element(in, name);

  if (el)
  {
    for (const EnumPair *p = pairs; p->name; p++)
    {
      if (str_eq(p->name, el->text))
        return p->value;
    }

    XmlLocation loc = el->text ? el->text_loc : el->name_loc;
    error(parser, loc, "expected '%s' value", name);
  }
  else if (!optional)
    missing_mandatory(parser, in, name);

  return def;
}

//-----------------------------------------------------------------------------
static int get_access(SvdParser *parser, XmlElement *element, int def)
{
  static const EnumPair pairs[] =
  {
    { "read-only",      SvdAccess_ReadOnly },
    { "write-only",     SvdAccess_WriteOnly },
    { "read-write",     SvdAccess_ReadWrite },
    { "writeOnce",      SvdAccess_WriteOnce },
    { "read-writeOnce", SvdAccess_ReadWriteOnce },
    { NULL, 0 },
  };
  return get_enum(parser, element, "access", pairs, true, def);
}

//-----------------------------------------------------------------------------
static int get_mod_write(SvdParser *parser, XmlElement *element, int def)
{
  static const EnumPair pairs[] =
  {
    { "oneToClear",   SvdModWrite_OneToClear },
    { "oneToSet",     SvdModWrite_OneToSet },
    { "oneToToggle",  SvdModWrite_OneToToggle },
    { "zeroToClear",  SvdModWrite_ZeroToClear },
    { "zeroToSet",    SvdModWrite_ZeroToSet },
    { "zeroToToggle", SvdModWrite_ZeroToToggle },
    { "clear",        SvdModWrite_Clear },
    { "set",          SvdModWrite_Set },
    { "modify",       SvdModWrite_Modify },
    { NULL, 0 },
  };
  return get_enum(parser, element, "modifiedWriteValues", pairs, true, def);
}

//-----------------------------------------------------------------------------
static int get_read_action(SvdParser *parser, XmlElement *element, int def)
{
  static const EnumPair pairs[] =
  {
    { "clear",          SvdReadAction_Clear },
    { "set",            SvdReadAction_Set },
    { "modify",         SvdReadAction_Modify },
    { "modifyExternal", SvdReadAction_ModifyExt },
    { NULL, 0 },
  };
  return get_enum(parser, element, "readAction", pairs, true, def);
}

//-----------------------------------------------------------------------------
static int get_enum_usage(SvdParser *parser, XmlElement *element, int def)
{
  static const EnumPair pairs[] =
  {
    { "read",       SvdEnumUsage_Read },
    { "write",      SvdEnumUsage_Write },
    { "read-write", SvdEnumUsage_ReadWrite },
    { NULL, 0 },
  };
  return get_enum(parser, element, "usage", pairs, true, def);
}

//-----------------------------------------------------------------------------
static int get_protection(SvdParser *parser, XmlElement *element, int def)
{
  static const EnumPair pairs[] =
  {
    { "s", SvdProtection_Secure },
    { "n", SvdProtection_NonSecure },
    { "p", SvdProtection_Privileged },
    { NULL, 0 },
  };
  return get_enum(parser, element, "protection", pairs, true, def);
}

//-----------------------------------------------------------------------------
static SvdWriteConstr get_write_constr(SvdParser *parser, XmlElement *element)
{
  XmlElement *constr = find_element(element, "writeConstraint");

  if (!constr)
    return (SvdWriteConstr){ SvdWriteConstrType_Undefined, 0, 0 };

  if (get_bool(parser, constr, "writeAsRead", true, false))
    return (SvdWriteConstr){ SvdWriteConstrType_WriteAsRead, 0, 0 };

  if (get_bool(parser, constr, "useEnumeratedValues", true, false))
    return (SvdWriteConstr){ SvdWriteConstrType_UseEnum, 0, 0 };

  XmlElement *range = find_element(element, "range");

  if (range)
  {
    u64 min = get_snn(parser, range, "minimum", false, 0);
    u64 max = get_snn(parser, range, "maximum", false, 0);
    return (SvdWriteConstr){ SvdWriteConstrType_Range, min, max };
  }

  error(parser, constr->name_loc, "unsupported constraint type");

  return (SvdWriteConstr){ SvdWriteConstrType_Undefined, 0, 0 };
}

//-----------------------------------------------------------------------------
static int get_size(SvdParser *parser, XmlElement *element, int def)
{
  int size = get_snn(parser, element, "size", true, def);

  if (size == 8 || size == 16 || size == 32)
    return size;
  else if (size < 8)
    size = 8;
  else if (size < 16)
    size = 16;
  else if (size < 32)
    size = 32;
  else
  {
    error(parser, element->name_loc, "unsupported size value (%d)", size);
    return size;
  }

  error(parser, element->name_loc, "size was rounded up to %d bits", size);

  return size;
}

//-----------------------------------------------------------------------------
static char *strip_array_index(char *name)
{
  char *src = name;
  char *dst = name;

  os_assert(name);

  while (src[0])
  {
    if (src[0] == '[' && src[1] == '%' && src[2] == 's' && src[3] == ']')
      src += 4;
    else if (src[0] == '_' && src[1] == '%' && src[2] == 's')
      src += 3;
    else if (src[0] == '%' && src[1] == 's')
      src += 2;
    else
      *dst++ = *src++;
  }

  dst[0] = 0;

  return name;
}

//-----------------------------------------------------------------------------
static char *strip_name(char *name)
{
  if (!name)
    return NULL;

  int len = strlen(name);

  while (len && name[len-1] == '_')
    len--;

  name[len] = 0;

  return len ? name : NULL;
}

//-----------------------------------------------------------------------------
static char *get_indexed_str(SvdParser *parser, char *name, char *index)
{
  int name_len  = strlen(name);
  int index_len = strlen(index);
  char *res = os_arena_alloc(parser->arena, name_len + index_len);
  char *pos = strstr(name, "%s");
  int la = pos - name;
  int lb = name_len - la - 2;

  os_assert(pos && la >= 0 && lb >= 0);

  memmove(res, name, la);
  memmove(res + la, index, index_len);
  memmove(res + la + index_len, pos + 2, lb);
  res[la + index_len + lb] = 0;

  return res;
}

//-----------------------------------------------------------------------------
static void fill_sequential_dim_names(SvdParser *parser, char *name, int start, SvdDim *dim)
{
  for (int i = 0; i < dim->size; i++)
  {
    char index[16];
    snprintf(index, sizeof(index), "%d", start + i);
    dim->names[i] = get_indexed_str(parser, name, index);
  }
}

//-----------------------------------------------------------------------------
static void parse_dim_index(SvdParser *parser, XmlElement *element, char *str, char *name, SvdDim *dim)
{
  int start, end;

  if (isalpha(str[0]) && (str[1] == '-') && isalpha(str[2]) && (str[3] == 0))
  {
    start = toupper(str[0]) - 'A';
    end   = toupper(str[2]) - 'A';

    if ((end - start + 1) < dim->size)
      return error(parser, element->name_loc, "alpha range is too short for a given array size: '%s'", name);

    for (int i = 0; i < dim->size; i++)
    {
      char index[2] = { start + 'A' + i, 0 };
      dim->names[i] = get_indexed_str(parser, name, index);
    }

    dim->sequential = false;
  }
  else if (strstr(str, "-"))
  {
    start = strtoul(str, &str, 10);

    if (str[0] != '-')
      return error(parser, element->name_loc, "malformed start of the range: '%s'", name);

    end = strtoul(&str[1], &str, 10);

    if (str[0] != 0)
      return error(parser, element->name_loc, "malformed end of the range: '%s'", name);

    if ((end - start + 1) < dim->size)
      return error(parser, element->name_loc, "numerical range is too short for a given array size: '%s'", name);

    fill_sequential_dim_names(parser, name, start, dim);

    dim->sequential = (start == 0);
  }
  else
  {
    int index = 0;
    int size = 0;
    char buf[128];

    dim->sequential = true;

    for (int i = 0; ; i++)
    {
      if (str[i] == ',' || str[i] == 0)
      {
        buf[size++] = 0;

        if (size == 1)
          return error(parser, element->name_loc, "empty name specified: '%s'", name);

        if (dim->sequential)
        {
          char *end;
          int value = strtoul(buf, &end, 10);
          if ((value != index) || (end[0] != 0))
            dim->sequential = false;
        }

        dim->names[index] = get_indexed_str(parser, name, buf);
        size = 0;

        if (index++ == dim->size || str[i] == 0)
          break;

        continue;
      }

      if (isspace(str[i]))
        continue;

      buf[size++] = str[i];

      if (size == sizeof(buf))
        return error(parser, element->name_loc, "name is too long: '%s'", name);
    }

    if (index < dim->size)
      return error(parser, element->name_loc, "name list is too short for a given array size: '%s'", name);
  }
}

//-----------------------------------------------------------------------------
static void get_dim(SvdParser *parser, XmlElement *element, SvdDim *dim, bool is_field)
{
  if (!find_element(element, "dim"))
    return;

  if (find_element(element, "dimArrayIndex"))
    return error(parser, element->name_loc, "'dimArrayIndex' is not supported");

  if (find_element(element, "dimName"))
    return error(parser, element->name_loc, "'dimName' is not supported");

  dim->size      = get_snn(parser, element, "dim", false, 0);
  dim->increment = get_snn(parser, element, "dimIncrement", false, 0);
  char *index    = get_str(parser, element, "dimIndex", true, NULL);
  char *name     = get_str(parser, element, "name", false, NULL);

  if (!name)
    return;

  if (dim->increment == 0)
    return error(parser, element->name_loc, "dimension increment must be greater than 0");
  else if (dim->size == 0)
    return error(parser, element->name_loc, "array size must be greater than 0");
  else if (dim->size > parser->opt->max_dim_size)
    return error(parser, element->name_loc, "array size %d is too big", dim->size);
  else if (is_field && dim->size > MAX_FIELD_DIM_SIZE)
    return error(parser, element->name_loc, "maximum field index size is %d", MAX_FIELD_DIM_SIZE);

  if (!strstr(name, "%s"))
    return error(parser, element->name_loc, "name must contain %%s");

  if (NULL == strstr(name, "[%s]"))
  {
    dim->names = os_arena_alloc(parser->arena, dim->size * sizeof(char *));

    if (index)
    {
      XmlElement *el = find_element(element, "dimIndex");
      parse_dim_index(parser, el, index, name, dim);
    }
    else
    {
      fill_sequential_dim_names(parser, name, 0, dim);
      dim->sequential = true;
    }
  }

  if (is_field && !dim->names)
    return error(parser, element->name_loc, "arrays of fileds are not supported");

  if (dim->sequential && parser->opt->convert_sequential_index_to_array)
  {
    dim->names = NULL;
    warning(parser, element->name_loc, "converted sequential index into an array for '%s'", name);
  }
}

//-----------------------------------------------------------------------------
static bool enum_value_str_to_value_and_mask(char *str, u32 *value, u32 *mask, int size)
{
  int base = 10;

  if (str[0] == '+')
    str++;

  if (str[0] == '0' && tolower(str[1]) == 'x')
  {
    base = 16;
    str += 2;
  }
  else if (str[0] == '0' && str[1] == 'b')
  {
    base = 2;
    str += 2;
  }
  else if (str[0] == '#')
  {
    base = 2;
    str += 1;
  }

  if (base == 2)
  {
    *value = 0;
    *mask  = 0;

    while (1)
    {
      int v, m;

      if (str[0] == '0' || str[0] == '1')
      {
        v = str[0] - '0';
        m = 1;
      }
      else if (tolower(str[0]) == 'x')
      {
        v = 0;
        m = 0;
      }
      else
        break;

      *value = (*value << 1) | v;
      *mask  = (*mask << 1) | m;

      str++;
    }
  }
  else
  {
    *value = strtoul(str, &str, base);
    *mask = (1ul << size) - 1;
  }

  if (str[0] != 0)
    return false;

  return true;
}

//-----------------------------------------------------------------------------
static SvdEnumValue *parse_enumerated_value(SvdParser *parser, XmlElement *element, int size)
{
  SvdEnumValue *value = os_arena_alloc(parser->arena, sizeof(SvdEnumValue));

  parser->error = false;

  value->name        = get_name(parser, element);
  value->description = get_str(parser, element, "description", true, NULL);

  if (parser->error)
    return NULL;

  XmlElement *value_el = find_element(element, "value");
  XmlElement *is_default_el = find_element(element, "isDefault");

  if (value_el)
  {
    if (!value_el->text)
    {
      error(parser, element->name_loc, "missing value string");
      return NULL;
    }

    if (!enum_value_str_to_value_and_mask(value_el->text, &value->value, &value->mask, size))
    {
      error(parser, element->name_loc, "malformed value string");
      return NULL;
    }
  }
  else if (is_default_el)
  {
    value->is_default = true;
  }
  else
  {
    error(parser, element->name_loc, "expected a value or 'isDefault' element");
    return NULL;
  }

  return value;
}

//-----------------------------------------------------------------------------
static void derive_enumeration(SvdParser *parser, XmlElement *element, SvdField *field, SvdEnumeration *enumeration)
{
  char *derived = get_attribute_value(element, "derivedFrom");

  if (!derived)
    return;

  if (str_eq(derived, field->r_values->name))
  {
    *enumeration = *field->r_values;
    enumeration->derived = field->r_values;
    return;
  }
  else if (str_eq(derived, field->w_values->name))
  {
    *enumeration = *field->w_values;
    enumeration->derived = field->w_values;
    return;
  }

  error(parser, element->name_loc, "enumeratedValues '%s' not found", derived);
}

//-----------------------------------------------------------------------------
static SvdEnumeration *parse_enumeration(SvdParser *parser, XmlElement *element, SvdField *field)
{
  SvdEnumeration *enumeration = os_arena_alloc(parser->arena, sizeof(SvdEnumeration));

  parser->error = false;

  derive_enumeration(parser, element, field, enumeration);

  enumeration->name        = get_str(parser, element, "name", true, enumeration->name);
  enumeration->header_name = get_str(parser, element, "headerEnumName", true, enumeration->header_name);
  enumeration->usage       = get_enum_usage(parser, element, enumeration->usage);

  if (parser->error)
    return NULL;

  for (XmlElement *el = element->elements; el; el = el->next)
  {
    if (!str_eq(el->name, "enumeratedValue"))
      continue;

    SvdEnumValue *value = parse_enumerated_value(parser, el, field->size);

    if (!value)
      continue;

    if (value->value <= ((1ul << field->size) - 1))
    {
      if (enumeration->derived)
      {
        enumeration->derived = NULL;
        list_dup(parser, enumeration->values);
      }
      list_add_sorted(enumeration->values, value, value);
    }
    else
      error(parser, element->name_loc, "enumerated value '%s' (%d) does not fit into the field", value->name, value->value);
  }

  if (!enumeration->values)
  {
    error(parser, element->name_loc, "'enumeratedValues' element must contain at least one value");
    return NULL;
  }

  return enumeration;
}

//-----------------------------------------------------------------------------
static void get_bit_pos_size(SvdParser *parser, XmlElement *element, SvdField *field)
{
  char *str = get_str(parser, element, "bitRange", true, NULL);

  field->lsb = -1;
  field->msb = -1;

  if (find_element(element, "lsb") || find_element(element, "msb"))
  {
    field->lsb = get_snn(parser, element, "lsb", false, 0);
    field->msb = get_snn(parser, element, "msb", false, 0);
  }
  else if (find_element(element, "bitOffset"))
  {
    field->lsb = get_snn(parser, element, "bitOffset", false, 0);
    field->msb = get_snn(parser, element, "bitWidth", true, 1) + field->lsb - 1;
  }
  else if (str)
  {
    if (str[0] == '[')
    {
      field->msb = strtoul(&str[1], &str, 10);

      if (str[0] == ':')
        field->lsb = strtoul(&str[1], &str, 10);
    }

    if (field->msb == -1 || field->lsb == -1 || str[0] != ']' || str[1] != 0)
      error(parser, element->name_loc, "inalid bit range specification");
  }
  else
  {
    error(parser, element->name_loc, "missing bit range specification");
  }

  field->size = field->msb - field->lsb + 1;
}

//-----------------------------------------------------------------------------
static void derive_field(SvdParser *parser, XmlElement *element, SvdItem *reg, SvdField *field)
{
  char *derived = get_attribute_value(element, "derivedFrom");

  if (!derived)
    return;

  for (SvdField *fld = reg->fields; fld; fld = fld->next)
  {
    if (str_eq(fld->name, derived))
    {
      *field = *fld;
      field->derived = fld;
      return;
    }
  }

  error(parser, element->name_loc, "field '%s' not found", derived);
}

//-----------------------------------------------------------------------------
static SvdField *parse_field(SvdParser *parser, XmlElement *element, SvdItem *reg)
{
  SvdField *field = os_arena_alloc(parser->arena, sizeof(SvdField));

  parser->error = false;

  derive_field(parser, element, reg, field);

  get_dim(parser, element, &field->dim, true);

  field->type         = SvdFieldType_Field;
  field->name         = get_name(parser, element);
  field->description  = get_str(parser, element, "description", true, field->description);
  field->access       = get_access(parser, element, field->access);
  field->mod_write    = get_mod_write(parser, element, field->mod_write);
  field->write_constr = get_write_constr(parser, element);
  field->read_action  = get_read_action(parser, element, field->read_action);

  get_bit_pos_size(parser, element, field);

  if (parser->error)
    return NULL;

  for (XmlElement *el = element->elements; el; el = el->next)
  {
    if (!str_eq(el->name, "enumeratedValues"))
      continue;

    SvdEnumeration *enumeration = parse_enumeration(parser, el, field);

    if (!enumeration)
      continue;

    if (SvdEnumUsage_Undefined == enumeration->usage)
      enumeration->usage = SvdEnumUsage_ReadWrite;

    if (SvdEnumUsage_Read == enumeration->usage)
      field->r_values = enumeration;
    else if (SvdEnumUsage_Write == enumeration->usage)
      field->w_values = enumeration;
    else if (SvdEnumUsage_ReadWrite == enumeration->usage)
      field->r_values = field->w_values = enumeration;

    field->derived = NULL;
  }

  return field;
}

//-----------------------------------------------------------------------------
static bool check_field(SvdParser *parser, XmlElement *element, SvdItem *reg, SvdField *field)
{
  if (field->msb >= (int)reg->size)
  {
    error(parser, element->name_loc, "field '%s' overflows the register '%s'", field->name, reg->name);
    return false;
  }

  u64 field_mask = ((1ul << field->size) - 1) << field->lsb;

  for (SvdField *fld = reg->fields; fld; fld = fld->next)
  {
    if (SvdFieldType_Field == fld->type)
    {
      u64 fld_mask = ((1ul << fld->size) - 1) << fld->lsb;

      if (fld_mask & field_mask)
      {
        error(parser, element->name_loc, "field '%s' overlaps field '%s'", field->name, fld->name);
        return false;
      }
    }
  }

  return true;
}

//-----------------------------------------------------------------------------
static void register_add_field(SvdParser *parser, SvdItem *reg, SvdField *field)
{
  if (reg->derived)
  {
    reg->derived = NULL;
    list_dup(parser, reg->fields);
  }

  list_add_sorted(reg->fields, field, lsb);
}

//-----------------------------------------------------------------------------
static void parse_fields(SvdParser *parser, XmlElement *element, SvdItem *reg)
{
  for (XmlElement *el = element->elements; el; el = el->next)
  {
    if (!str_eq(el->name, "field"))
    {
      error(parser, el->name_loc, "not a field element '%s'", el->name);
      continue;
    }

    SvdField *field = parse_field(parser, el, reg);

    if (!field)
      continue;

    if (!check_field(parser, el, reg, field))
      continue;

    if (field->dim.size == 0)
    {
      register_add_field(parser, reg, field);
      continue;
    }

    field->type = SvdFieldType_Template;

    for (int i = 0; i < field->dim.size; i++)
    {
      SvdField *fld = os_arena_alloc(parser->arena, sizeof(SvdField));

      *fld = *field;
      fld->type = SvdFieldType_Field;
      fld->ref  = field;
      fld->name = field->dim.names[i];
      fld->lsb  = field->lsb + field->dim.increment * i;
      fld->msb  = field->msb + field->dim.increment * i;
      fld->size = fld->msb - fld->lsb + 1;

      if (!check_field(parser, el, reg, fld))
        continue;

      register_add_field(parser, reg, fld);
    }
  }
}

//-----------------------------------------------------------------------------
static void get_alternate_item(SvdParser *parser, XmlElement *element, SvdItem *group, SvdItem *item)
{
  char *alt_str = (SvdItemType_Register == item->type) ? "alternateRegister" : "alternateCluster";

  item->alt_name = get_str(parser, element, alt_str, true, item->alt_name);

  if (!item->alt_name)
    return;

  for (SvdItem *it = group->items; it; it = it->next)
  {
    if (it->type == item->type && str_eq(it->name, item->alt_name))
    {
      item->alt = it;
      return;
    }
  }

  char *type_str = (SvdItemType_Register == item->type) ? "register" : "cluster";
  error(parser, element->name_loc, "alternate %s '%s' not found", type_str, item->alt_name);
}

//-----------------------------------------------------------------------------
static void update_item_properties(SvdParser *parser, XmlElement *element, SvdItem *item, SvdItem *def)
{
  item->size        = get_size(parser, element, def->size);
  item->access      = get_access(parser, element, def->access);
  item->protection  = get_protection(parser, element, def->protection);
  item->reset_value = get_snn(parser, element, "resetValue", true, def->reset_value);
  item->reset_mask  = get_snn(parser, element, "resetMask", true, def->reset_mask);
}

//-----------------------------------------------------------------------------
static void derive_item(SvdParser *parser, XmlElement *element, SvdItem *group, SvdItem *item, int type)
{
  char *derived = get_attribute_value(element, "derivedFrom");

  if (!derived)
  {
    update_item_properties(parser, element, item, group);
    return;
  }

  for (SvdItem *it = group->items; it; it = it->next)
  {
    if (it->type == type && str_eq(it->name, derived))
    {
      *item = *it;
      item->derived = it;
      update_item_properties(parser, element, item, item);
      return;
    }
  }

  char *type_str = (SvdItemType_Register == type) ? "register" : "cluster";
  error(parser, element->name_loc, "%s '%s' not found", type_str, derived);
}

//-----------------------------------------------------------------------------
static SvdItem *parse_register(SvdParser *parser, XmlElement *element, SvdItem *group)
{
  SvdItem *reg = os_arena_alloc(parser->arena, sizeof(SvdItem));

  parser->error = false;

  derive_item(parser, element, group, reg, SvdItemType_Register);

  get_dim(parser, element, &reg->dim, false);

  reg->type         = SvdItemType_Register;
  reg->loc          = element->name_loc;
  reg->name         = get_name(parser, element);
  reg->display_name = get_str(parser, element, "displayName", true, reg->display_name);
  reg->description  = get_str(parser, element, "description", true, reg->description);
  reg->alt_group    = get_str(parser, element, "alternateGroup", true, reg->alt_group);
  reg->offset       = get_snn(parser, element, "addressOffset", false, 0);
  reg->data_type    = get_str(parser, element, "dataType", true, reg->data_type);
  reg->mod_write    = get_mod_write(parser, element, reg->mod_write);
  reg->write_constr = get_write_constr(parser, element);
  reg->read_action  = get_read_action(parser, element, reg->read_action);

  get_alternate_item(parser, element, group, reg);

  if (parser->error)
    return NULL;

  XmlElement *fields = find_element(element, "fields");

  if (fields)
    parse_fields(parser, fields, reg);

  return reg;
}

//-----------------------------------------------------------------------------
static SvdItem *parse_cluster(SvdParser *parser, XmlElement *element, SvdItem *group)
{
  SvdItem *cluster = os_arena_alloc(parser->arena, sizeof(SvdItem));

  parser->error = false;

  derive_item(parser, element, group, cluster, SvdItemType_Cluster);

  get_dim(parser, element, &cluster->dim, false);

  cluster->type        = SvdItemType_Cluster;
  cluster->loc         = element->name_loc;
  cluster->name        = get_name(parser, element);
  cluster->description = get_str(parser, element, "description", true, cluster->description);
  cluster->struct_name = get_str(parser, element, "headerStructName", true, cluster->struct_name);
  cluster->offset      = get_snn(parser, element, "addressOffset", false, 0);

  get_alternate_item(parser, element, group, cluster);

  if (parser->error)
    return NULL;

  if (cluster->derived && cluster->derived->dim.increment != cluster->dim.increment)
  {
    error(parser, element->name_loc, "derived cluster '%s' must have the same increment as a reference cluster",
        cluster->name, cluster->offset);
    return NULL;
  }

  if (parser->cluster_depth == parser->opt->max_cluster_depth)
  {
    error(parser, element->name_loc, "maximum cluster nesting depth reached");
    return NULL;
  }

  parser->cluster_depth++;
  parse_group(parser, element, cluster);
  parser->cluster_depth--;

  if (!cluster->items)
    return NULL;

  return cluster;
}

//-----------------------------------------------------------------------------
static void group_add_item(SvdParser *parser, SvdItem *group, SvdItem *item)
{
  if (group->derived)
  {
    group->derived = NULL;
    list_dup(parser, group->items);
  }

  list_add_sorted(group->items, item, offset);
}

//-----------------------------------------------------------------------------
static void parse_group(SvdParser *parser, XmlElement *element, SvdItem *group)
{
  bool changed = false;

  for (XmlElement *el = element->elements; el; el = el->next)
  {
    SvdItem *item;

    if (str_eq(el->name, "register"))
      item = parse_register(parser, el, group);
    else if (str_eq(el->name, "cluster"))
      item = parse_cluster(parser, el, group);
    else
      continue;

    if (!item)
      continue;

    changed = true;
    group_add_item(parser, group, item);
  }

  if (!changed)
    return;

  for (SvdItem *item = group->items; item; item = item->next)
  {
    if (item->dim.size == 0)
      continue;

    if (item->dim.names)
    {
      for (int i = 0; i < item->dim.size; i++)
      {
        SvdItem *it = os_arena_alloc(parser->arena, sizeof(SvdItem));
        *it = *item;
        it->ref    = item;
        it->name   = item->dim.names[i];
        it->dim    = (SvdDim){0};
        it->offset = item->offset + item->dim.increment * i;
        group_add_item(parser, group, it);
      }

      item->type = SvdItemType_Template;
    }
    else
    {
      item->name = strip_array_index(item->name);
    }
  }
}

//-----------------------------------------------------------------------------
static void remove_group_prefix(SvdItem *group)
{
  if (group->prefix_done || !group->items)
    return;

  char *ref = group->items->name;
  int len = 0;

  for (int i = 0; ref[i] && len == 0; i++)
  {
    if (ref[i] == '_')
      len = i + 1;
  }

  if (!group->items->next) // Do not match groups with one item
    len = 0;

  if ('0' <= ref[len] && ref[len] <= '9')
    len = 0;

  for (SvdItem *item = group->items; item; item = item->next)
  {
    if (SvdItemType_Cluster == item->type)
      remove_group_prefix(item);

    if (len && 0 != strncmp(ref, item->name, len))
      len = 0;
  }

  if (len)
  {
    for (SvdItem *item = group->items; item; item = item->next)
      item->name += len;
  }

  group->prefix_done = true;
}

//-----------------------------------------------------------------------------
static bool check_register_alignment(SvdParser *parser, SvdItem *reg, u32 base)
{
  os_assert(SvdItemType_Register == reg->type);

  if (0 == ((base + reg->offset) % (reg->size / BITS_IN_BYTE)))
    return true;

  error(parser, reg->loc, "register '%s' is not aligned (address = 0x%x, size = %d bits)",
      reg->name, base + reg->offset, reg->size);

  return false;
}

//-----------------------------------------------------------------------------
static SvdLayout *make_register_layout(SvdParser *parser, SvdItem *reg)
{
  SvdLayout *layout = os_arena_alloc(parser->arena, sizeof(SvdLayout));

  os_assert(SvdItemType_Register == reg->type);

  layout->type        = SvdLayoutType_Register;
  layout->name        = reg->name;
  layout->description = reg->description;
  layout->struct_name = reg->struct_name;
  layout->derived     = reg->derived ? reg->derived->name : NULL;
  layout->dim         = reg->dim.size;
  layout->increment   = reg->dim.increment;
  layout->access      = reg->access;
  layout->offset      = reg->offset;
  layout->size        = reg->size / BITS_IN_BYTE;
  layout->total_size  = layout->size;
  layout->fields      = reg->fields;

  return layout;
}

//-----------------------------------------------------------------------------
static SvdLayout *infer_register_group(SvdParser *parser, SvdItem **item, u32 base, int index)
{
  SvdItem *start = *item;
  SvdItem *end = NULL;
  u32 offset = start->offset + (start->size / BITS_IN_BYTE);

  if (NULL == start->next || 0 == start->dim.size)
    return NULL;

  for (SvdItem *it = start->next; it; it = it->next)
  {
    if (it->offset < offset || SvdItemType_Register != it->type ||
        start->dim.size != it->dim.size || start->dim.increment != it->dim.increment)
      break;

    offset = it->offset + (it->size / BITS_IN_BYTE);

    if ((offset - start->offset) > start->dim.increment)
      break;

    end = it;
  }

  if (NULL == end)
    return NULL;

  warning(parser, start->loc, "identified register group '%s'...'%s'", start->name, end->name);

  char *group_name = "Group";

  if (index > 0)
  {
    group_name = os_arena_alloc(parser->arena, 16);
    snprintf(group_name, 16, "Group%d", index);
  }

  SvdLayout *layout = os_arena_alloc(parser->arena, sizeof(SvdLayout));

  layout->type      = SvdLayoutType_Struct;
  layout->name      = group_name;
  layout->offset    = start->offset;
  layout->dim       = start->dim.size;
  layout->increment = start->dim.increment;

  for (SvdItem *it = start; ; it = it->next)
  {
    if (!check_register_alignment(parser, it, base))
      continue;

    SvdLayout *reg = make_register_layout(parser, it);

    reg->offset    = reg->offset - start->offset;
    reg->dim       = 0;
    reg->increment = 0;

    list_add_sorted(layout->items, reg, offset);

    if (it == end)
      break;
  }

  *item = end;

  return layout;
}

//-----------------------------------------------------------------------------
static SvdLayout *layout_group_alloc(SvdParser *parser, SvdLayout *item)
{
  SvdLayout *group;

  if (parser->layouts)
  {
    group = parser->layouts;
    parser->layouts = parser->layouts->next;
    *group = (SvdLayout){0};
  }
  else
  {
    group = os_arena_alloc(parser->arena, sizeof(SvdLayout));
  }

  group->type  = SvdLayoutType_UnionGroup;
  group->items = item;
  group->total_size = item->offset + item->total_size;

  return group;
}

//-----------------------------------------------------------------------------
static void add_to_union(SvdParser *parser, SvdLayout *union_layout, SvdLayout *item)
{
  SvdLayout *place = NULL;

  item->offset -= union_layout->offset;

  for (SvdLayout *it = union_layout->items; it && !place; it = it->next)
  {
    os_assert(SvdLayoutType_UnionGroup == it->type);

    for (SvdLayout *i = it->items; i && !place; i = i->next)
    {
      if (item->offset >= i->offset)
        continue;

      if (item->total_size <= (i->offset - item->offset))
        place = it;
    }

    if (!place && (item->offset >= it->total_size))
      place = it;
  }

  if (place)
  {
    list_add_sorted(place->items, item, offset);
    place->total_size = os_max(place->total_size, item->offset + item->total_size);
  }
  else
  {
    SvdLayout *group = layout_group_alloc(parser, item);
    list_add_sorted(union_layout->items, group, total_size);
  }

  union_layout->size = os_max(union_layout->total_size, item->offset + item->total_size);
  union_layout->total_size = union_layout->size;
}

//-----------------------------------------------------------------------------
static void fold_union_groups(SvdParser *parser, SvdLayout *union_layout)
{
  for (SvdLayout *item = union_layout->items; item; item = item->next)
  {
    os_assert(SvdLayoutType_UnionGroup == item->type);

    if (item->items->next || item->items->offset > 0)
    {
      item->type = SvdLayoutType_Struct;
      continue;
    }

    SvdLayout *inner = item->items;
    inner->next = item->next;
    *item = *inner;

    inner->next = parser->layouts;
    parser->layouts = inner;
  }
}

//-----------------------------------------------------------------------------
static SvdLayout *generate_layout(SvdParser *parser, SvdItem *group, u32 base)
{
  SvdLayout *layout = os_arena_alloc(parser->arena, sizeof(SvdLayout));
  SvdLayout *current_item = NULL;
  u32 offset = 0;
  int index = 0;

  layout->type = SvdLayoutType_Struct;
  layout->name = group->name;
  layout->struct_name = group->struct_name;

  for (SvdItem *it = group->items; it; it = it->next)
  {
    SvdLayout *item = NULL;

    if (SvdItemType_Cluster == it->type)
    {
      item = generate_layout(parser, it, base + it->offset);

      item->type        = SvdLayoutType_Cluster;
      item->name        = it->name;
      item->description = it->description;
      item->struct_name = it->struct_name;
      item->derived     = it->derived ? it->derived->name : NULL;
      item->offset      = it->offset;
      item->dim         = it->dim.size;
      item->increment   = it->dim.increment;
    }
    else if (SvdItemType_Register == it->type)
    {
      if (!check_register_alignment(parser, it, base))
        continue;

      if (parser->opt->infer_register_groups)
        item = infer_register_group(parser, &it, base, index);

      if (item)
        index++;
      else
        item = make_register_layout(parser, it);
    }
    else
      continue;

    os_assert(item);

    if (item->dim > 0)
    {
      if (item->size > item->increment)
      {
        error(parser, it->loc, "array '%s' increment (%d) is smaller than the element size (%d)",
            item->name, item->increment, item->size);
        continue;
      }

      if (SvdLayoutType_Register == item->type && item->increment > item->size)
      {
        SvdLayout *struct_item = os_arena_alloc(parser->arena, sizeof(SvdLayout));

        struct_item->type      = SvdLayoutType_Struct;
        struct_item->name      = item->name;
        struct_item->offset    = item->offset;
        struct_item->dim       = item->dim;
        struct_item->increment = item->increment;
        struct_item->items     = item;

        item->name      = "v";
        item->offset    = 0;
        item->dim       = 0;
        item->increment = 0;

        item = struct_item;

        warning(parser, it->loc, "converted sparse array '%s' into array of structures", item->name);
      }

      if (SvdLayoutType_Union == item->type || SvdLayoutType_Struct == item->type ||
          SvdLayoutType_Cluster == item->type)
      {
        item->size = item->increment;
      }

      item->total_size = item->dim * item->increment;
    }

    if (item->offset >= offset)
    {
      if (current_item)
        list_add_sorted(layout->items, current_item, offset);

      current_item = item;
    }
    else
    {
      if (SvdLayoutType_Union != current_item->type)
      {
        SvdLayout *union_item = os_arena_alloc(parser->arena, sizeof(SvdLayout));

        union_item->type   = SvdLayoutType_Union;
        union_item->offset = current_item->offset;

        add_to_union(parser, union_item, current_item);

        current_item = union_item;
      }

      add_to_union(parser, current_item, item);
    }

    offset = os_max(offset, item->offset + item->total_size);

    layout->size = offset;
    layout->total_size = layout->size;
  }

  if (current_item)
  {
    list_add_sorted(layout->items, current_item, offset);

    layout->size = os_max(offset, current_item->offset + current_item->total_size);
    layout->total_size = layout->size;
  }

  for (SvdLayout *item = layout->items; item; item = item->next)
  {
    if (SvdLayoutType_Union == item->type)
      fold_union_groups(parser, item);
  }

  if (SvdLayoutType_Struct == layout->type && layout->items && NULL == layout->items->next && 0 == layout->items->dim &&
      (SvdLayoutType_Struct == layout->items->type || SvdLayoutType_Union == layout->items->type))
  {
    layout->items->name = layout->name;
    layout->items->struct_name = layout->struct_name;
    return layout->items;
  }

  return layout;
}

//-----------------------------------------------------------------------------
static void derive_peripheral(SvdParser *parser, XmlElement *element, SvdPeripheral *per)
{
  char *derived = get_attribute_value(element, "derivedFrom");

  if (!derived)
  {
    per->size        = get_size(parser, element, parser->size);
    per->access      = get_access(parser, element, parser->access);
    per->protection  = get_protection(parser, element, parser->protection);
    per->reset_value = get_snn(parser, element, "resetValue", true, parser->reset_value);
    per->reset_mask  = get_snn(parser, element, "resetMask", true, parser->reset_mask);
    return;
  }

  for (SvdPeripheral *p = parser->device->peripherals; p; p = p->next)
  {
    if (str_eq(p->name, derived))
    {
      *per = *p;
      per->derived     = p;
      per->size        = get_size(parser, element, per->size);
      per->access      = get_access(parser, element, per->access);
      per->protection  = get_protection(parser, element, per->protection);
      per->reset_value = get_snn(parser, element, "resetValue", true, per->reset_value);
      per->reset_mask  = get_snn(parser, element, "resetMask", true, per->reset_mask);
      return;
    }
  }

  error(parser, element->name_loc, "peripheral '%s' not found", derived);
}

//-----------------------------------------------------------------------------
static SvdPeripheral *parse_peripheral(SvdParser *parser, XmlElement *element)
{
  SvdPeripheral *per = os_arena_alloc(parser->arena, sizeof(SvdPeripheral));

  parser->error = false;

  derive_peripheral(parser, element, per);

  get_dim(parser, element, &per->dim, false);

  per->name         = get_name(parser, element);
  per->version      = get_str(parser, element, "version", true, per->version);
  per->description  = get_str(parser, element, "description", true, per->description);
  per->alt_per      = get_str(parser, element, "alternatePeripheral", true, per->alt_per);
  per->group_name   = get_str(parser, element, "groupName", true, per->group_name);
  per->prepend      = strip_name(get_str(parser, element, "prependToName", true, per->prepend));
  per->append       = strip_name(get_str(parser, element, "appendToName", true, per->append));
  per->struct_name  = get_str(parser, element, "headerStructName", true, per->struct_name);
  per->disable_cond = get_str(parser, element, "disableCondition", true, per->disable_cond);
  per->base_addr    = get_snn(parser, element, "baseAddress", false, 0);

  if (parser->error)
    return NULL;

  per->registers.name        = per->name;
  per->registers.struct_name = per->struct_name;
  per->registers.size        = per->size;
  per->registers.access      = per->access;
  per->registers.protection  = per->protection;
  per->registers.reset_value = per->reset_value;
  per->registers.reset_mask  = per->reset_mask;

  for (XmlElement *el = element->elements; el; el = el->next)
  {
    if (str_eq(el->name, "interrupt"))
    {
      SvdInterrupt *interrupt = os_arena_alloc(parser->arena, sizeof(SvdInterrupt));
      bool exists = false;

      parser->error = false;

      interrupt->name        = get_name(parser, el);
      interrupt->index       = get_snn(parser, el, "value", false, 0);
      interrupt->description = get_str(parser, el, "description", true, NULL);
      interrupt->peripheral  = per;

      if (parser->error)
        continue;

      for (SvdInterrupt *intr = parser->device->interrupts; intr && !exists; intr = intr->next)
      {
        if (0 == strcmp(interrupt->name, intr->name))
          exists = true;
      }

      if (!exists)
        list_add_sorted(parser->device->interrupts, interrupt, index);
    }
    else if (str_eq(el->name, "registers"))
    {
      if (per->derived)
      {
        per->derived = NULL;
        list_dup(parser, per->registers.items);
      }

      parse_group(parser, el, &per->registers);
    }
  }

  if (parser->opt->remove_group_prefix)
    remove_group_prefix(&per->registers);

  if (parser->opt->generate_layout)
  {
    per->layout = generate_layout(parser, &per->registers, per->base_addr);
    per->layout->derived = per->derived ? per->derived->name : NULL;
  }

  return per;
}

//-----------------------------------------------------------------------------
static void parse_peripherals(SvdParser *parser, XmlElement *element)
{
  for (XmlElement *el = element->elements; el; el = el->next)
  {
    if (!str_eq(el->name, "peripheral"))
    {
      error(parser, el->name_loc, "not a peripheral element '%s'", el->name);
      continue;
    }

    SvdPeripheral *per = parse_peripheral(parser, el);

    if (!per)
      continue;

    if (per->dim.size)
    {
      error(parser, element->name_loc, "peripheral arrays are not supported");
      continue;
    }

    list_add_sorted(parser->device->peripherals, per, base_addr);
  }

  if (!parser->device->peripherals)
    warning(parser, element->name_loc, "device has no peripherals");
}

//-----------------------------------------------------------------------------
static void get_cpu_revision(SvdParser *parser, XmlElement *element, SvdCpu *cpu)
{
  cpu->revision = get_str(parser, element, "revision", false, NULL);

  if (!cpu->revision)
    return;

  char *str = cpu->revision;

  if (str[0] != 'r')
    return error(parser, element->name_loc, "malformed CPU revision string: '%s'", cpu->revision);

  cpu->rev_r = strtoul(&str[1], &str, 10);

  if (str[0] != 'p')
    return error(parser, element->name_loc, "malformed CPU revision string: '%s'", cpu->revision);

  cpu->rev_p = strtoul(&str[1], &str, 10);

  if (str[0] != 0)
    return error(parser, element->name_loc, "malformed CPU revision string: '%s'", cpu->revision);
}

//-----------------------------------------------------------------------------
static void parse_cpu(SvdParser *parser, XmlElement *element)
{
  SvdCpu *cpu = &parser->device->cpu;

  cpu->name            = get_str(parser,  element, "name", false, NULL);
  cpu->endian          = get_str(parser,  element, "endian", false, NULL);
  cpu->mpu_present     = get_bool(parser, element, "mpuPresent", true, false);
  cpu->fpu_present     = get_bool(parser, element, "fpuPresent", true, false);
  cpu->fpu_dp          = get_bool(parser, element, "fpuDP", true, false);
  cpu->dsp_present     = get_bool(parser, element, "dspPresent", true, false);
  cpu->icache_present  = get_bool(parser, element, "icachePresent", true, false);
  cpu->dcache_present  = get_bool(parser, element, "dcachePresent", true, false);
  cpu->itcm_present    = get_bool(parser, element, "itcmPresent", true, false);
  cpu->dtcm_present    = get_bool(parser, element, "dtcmPresent", true, false);
  cpu->vtor_present    = get_bool(parser, element, "vtorPresent", true, false);
  cpu->vendor_systick  = get_bool(parser, element, "vendorSystickConfig", false, false);
  cpu->nvic_prio_bits  = get_snn(parser,  element, "nvicPrioBits", false, 0);
  cpu->num_interrupts  = get_snn(parser,  element, "deviceNumInterrupts", true, 0);
  cpu->sau_num_regions = get_snn(parser,  element, "sauNumRegions", true, 0);

  get_cpu_revision(parser, element, cpu);

  XmlElement *config = find_element(element, "sauRegionsConfig");

  if (config)
    warning(parser, config->name_loc, "'sauRegionsConfig' is not supported");

  cpu->valid = true;
}

//-----------------------------------------------------------------------------
static void parse_device(SvdParser *parser, XmlElement *element)
{
  SvdDevice *device = parser->device;

  if (!str_eq(element->name, "device"))
    return error(parser, element->name_loc, "expected 'device' element");

  if (!get_attribute_value(element, "schemaVersion"))
    warning(parser, element->name_loc, "missing mandatory 'schemaVersion' attribute");

  device->vendor            = get_str(parser, element, "vendor", true, NULL);
  device->vendor_id         = get_str(parser, element, "vendorID", true, NULL);
  device->name              = get_str(parser, element, "name", false, NULL);
  device->series            = get_str(parser, element, "series", true, NULL);
  device->version           = get_str(parser, element, "version", false, NULL);
  device->description       = get_str(parser, element, "description", true, NULL);
  device->license_text      = get_str(parser, element, "licenseText", true, NULL);
  device->header_filename   = get_str(parser, element, "headerSystemFilename", true, NULL);
  device->header_prefix     = get_str(parser, element, "headerDefinitionsPrefix", true, NULL);
  device->address_unit_bits = get_snn(parser, element, "addressUnitBits", false, 0);
  device->width             = get_snn(parser, element, "width", false, 0);

  parser->size        = get_size(parser, element, 32);
  parser->access      = get_access(parser, element, SvdAccess_ReadWrite);
  parser->protection  = get_protection(parser, element, SvdProtection_Undefined);
  parser->reset_value = get_snn(parser, element, "resetValue", true, 0);
  parser->reset_mask  = get_snn(parser, element, "resetMask", true, 0xffffffff);

  XmlElement *cpu = find_element(element, "cpu");
  if (cpu)
    parse_cpu(parser, cpu);

  if (parser->error)
    return;

  device->valid = true;

  XmlElement *peripherals = find_element(element, "peripherals");

  if (peripherals)
    parse_peripherals(parser, peripherals);
  else
    error(parser, element->name_loc, "'peripherals' element not found");

  XmlElement *extensions = find_element(element, "vendorExtensions");

  if (extensions)
    warning(parser, extensions->name_loc, "vendor extensions are ignored");
}

//-----------------------------------------------------------------------------
SvdFile *svd_parse(char *text, SvdOptions *options)
{
  SvdParser parser = {0};

  parser.opt = options ? options : &svd_default_options_val;

  parser.file = os_alloc(sizeof(SvdFile));
  parser.xml  = xml_parse(text);

  parser.file->arena  = os_arena_new(strlen(text));
  parser.file->device = os_arena_alloc(parser.file->arena, sizeof(SvdDevice));

  parser.arena  = parser.file->arena;
  parser.device = parser.file->device;

  if (parser.xml->error)
  {
    error(&parser, (XmlLocation){0}, parser.xml->error);
    xml_free(parser.xml);
    return parser.file;
  }

  parse_device(&parser, parser.xml->root);

  flush_messages(&parser);

  xml_free(parser.xml);

  return parser.file;
}

//-----------------------------------------------------------------------------
SvdOptions svd_default_options(void)
{
  return svd_default_options_val;
}

//-----------------------------------------------------------------------------
void svd_free(SvdFile *file)
{
  os_arena_free(file->arena);
  os_free(file);
}

