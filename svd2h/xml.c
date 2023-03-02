// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

/*- Includes ----------------------------------------------------------------*/
#include "xml.h"

/*- Definitions -------------------------------------------------------------*/
#define MAX_ERROR_LENGTH       64

/*- Types -------------------------------------------------------------------*/
typedef struct
{
  XmlFile      *file;
  char         *ptr;
  char         *start;
  int          line;
} XmlParser;

/*- Implementations ---------------------------------------------------------*/

//-----------------------------------------------------------------------------
static bool error(XmlParser *parser, char *text)
{
  int column = parser->ptr - parser->start;

  if (parser->file->error)
    return false;

  if (parser->line == 1)
    column++;

  parser->file->error = os_arena_alloc(parser->file->arena, MAX_ERROR_LENGTH);

  snprintf(parser->file->error, MAX_ERROR_LENGTH, "%d,%d: %s", parser->line, column, text);

  return false;
}

//-----------------------------------------------------------------------------
static inline bool is_white(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f';
}

//-----------------------------------------------------------------------------
static inline bool is_alpha(char c)
{
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

//-----------------------------------------------------------------------------
static inline bool is_digit(char c)
{
  return c >= '0' && c <= '9';
}

//-----------------------------------------------------------------------------
static void next(XmlParser *parser)
{
  if (parser->ptr[0] == 0)
    return;

  if (parser->ptr[0] == '\r' && parser->ptr[1] == '\n')
    parser->ptr++;

  if (parser->ptr[0] == '\r' || parser->ptr[0] == '\n')
  {
    parser->line++;
    parser->start = parser->ptr;
  }

  parser->ptr++;
}

//-----------------------------------------------------------------------------
static bool starts_with(XmlParser *parser, char *str)
{
  for (int i = 0; str[i]; i++)
  {
    if (parser->ptr[i] != str[i])
      return false;
  }
  return true;
}

//-----------------------------------------------------------------------------
static bool skip_until(XmlParser *parser, char *ending)
{
  // Note: This assumes that strings inside the block do not include 'ending' sequence.
  while (1)
  {
    if (parser->ptr[0] == 0)
      return error(parser, "unexpected end of input");

    if (starts_with(parser, ending))
      break;

    next(parser);
  }

  parser->ptr += strlen(ending);

  return true;
}

//-----------------------------------------------------------------------------
static bool skip_spaces(XmlParser *parser)
{
  while (1)
  {
    while (is_white(parser->ptr[0]))
      next(parser);

    if (!starts_with(parser, "<!--"))
      break;

    parser->ptr += 4;

    if (!skip_until(parser, "-->"))
      return false;
  }

  return true;
}

//-----------------------------------------------------------------------------
static int convert_entity_reference(char **str)
{
  static const struct
  {
    char *str;
    int  len;
    int  chr;
  } ent_refs[5] = {
    { "&lt;",   4, '<' },
    { "&gt;",   4, '>' },
    { "&amp;",  5, '&' },
    { "&apos;", 6, '\'' },
    { "&quot;", 6, '"' },
  };

  for (int i = 0; i < ARRAY_SIZE(ent_refs); i++)
  {
    if (0 == strncmp(*str, ent_refs[i].str, ent_refs[i].len))
    {
      *str += ent_refs[i].len-1;
      return ent_refs[i].chr;
    }
  }

  char *ptr = *str;

  if (ptr[0] == '&' && ptr[1] == '#')
  {
    for (int i = 0; (i < 16) && ptr[i]; i++)
    {
      if (ptr[i] == ';')
      {
        *str += i;
        return 0;
      }
    }
  }

  return -1;
}

//-----------------------------------------------------------------------------
static char *string_copy(XmlParser *parser, char *start, char *end)
{
  int size = end - start + 1;
  int len = 0;
  char *res;

  res = os_arena_alloc(parser->file->arena, size);

  for (char *ptr = start; ptr < end; ptr++)
  {
    int chr = *ptr;

    if (chr == '&')
    {
      chr = convert_entity_reference(&ptr);

      if (chr == -1)
      {
        error(parser, "unrecognized entity reference");
        return NULL;
      }
    }

    if (chr)
      res[len++] = chr;
  }

  res[len] = 0;

  return res;
}

//-----------------------------------------------------------------------------
static XmlLocation get_location(XmlParser *parser)
{
  XmlLocation loc;
  loc.line   = parser->line;
  loc.column = parser->ptr - parser->start;
  return loc;
}

//-----------------------------------------------------------------------------
static char *parse_name(XmlParser *parser)
{
  char *start = parser->ptr;

  if (!is_alpha(parser->ptr[0]) && parser->ptr[0] != '_')
    return NULL;

  while (is_alpha(parser->ptr[0]) || is_digit(parser->ptr[0]) || parser->ptr[0] == '-' ||
      parser->ptr[0] == '_' || parser->ptr[0] == '.' || parser->ptr[0] == ':')
  {
    next(parser);
  }

  return string_copy(parser, start, parser->ptr);
}

//-----------------------------------------------------------------------------
static char *parse_value(XmlParser *parser)
{
  char *start = parser->ptr + 1;
  int str_type = parser->ptr[0];

  if (parser->ptr[0] != '"' && parser->ptr[0] != '\'')
  {
    error(parser, "value expected");
    return NULL;
  }

  next(parser);

  while (parser->ptr[0] != 0 && parser->ptr[0] != '\n' && parser->ptr[0] != str_type)
  {
    next(parser);
  }

  if (parser->ptr[0] != str_type)
  {
    error(parser, "unterminated string");
    return NULL;
  }

  next(parser);

  return string_copy(parser, start, parser->ptr - 1);
}

//-----------------------------------------------------------------------------
static char *parse_text(XmlParser *parser)
{
  char *start = parser->ptr;

  while (parser->ptr[0] != 0 && parser->ptr[0] != '<')
  {
    next(parser);
  }

  if (parser->ptr[0] == 0)
  {
    error(parser, "unterminated element");
    return NULL;
  }

  char *end = parser->ptr;

  while (end != start && is_white(end[-1]))
    end--;

  return string_copy(parser, start, end);
}

//-----------------------------------------------------------------------------
static bool parse_closing_tag(XmlParser *parser, XmlElement *element)
{
  int len;

  if (parser->ptr[0] != '<' && parser->ptr[1] != '/')
    return error(parser, "closing tag expected");

  next(parser);
  next(parser);

  if (!skip_spaces(parser))
    return false;

  len = strlen(element->name);

  if (memcmp(parser->ptr, element->name, len))
    return error(parser, "closing tag expected");

  parser->ptr += len;

  if (!skip_spaces(parser))
    return false;

  if (parser->ptr[0] != '>')
    return error(parser, "'>' expected");

  next(parser);

  return true;
}

//-----------------------------------------------------------------------------
static bool parse_element(XmlParser *parser, XmlElement *element)
{
  if (!skip_spaces(parser))
    return false;

  if (parser->ptr[0] != '<')
    return error(parser, "opening tag expected");

  next(parser);

  memset(element, 0, sizeof(XmlElement));

  element->name_loc = get_location(parser);
  element->name     = parse_name(parser);

  if (!element->name)
    return error(parser, "element name expected");

  XmlAttribute *prev_attr = NULL;

  while (1)
  {
    if (!skip_spaces(parser))
      return false;

    if (parser->ptr[0] == '/' || parser->ptr[0] == '>')
      break;

    XmlAttribute *attr = os_arena_alloc(parser->file->arena, sizeof(XmlAttribute));

    attr->value    = NULL;
    attr->name_loc = get_location(parser);
    attr->name     = parse_name(parser);
    attr->parent   = element;

    if (!attr->name)
      return error(parser, "attribute name expected");

    if (!skip_spaces(parser))
      return false;

    if (parser->ptr[0] != '=')
      return error(parser, "'=' expected");

    next(parser);

    if (!skip_spaces(parser))
      return false;

    attr->value_loc = get_location(parser);
    attr->value     = parse_value(parser);

    if (!attr->value)
      return error(parser, "attribute value expected");

    if (prev_attr)
      prev_attr->next = attr;
    else
      element->attributes = attr;

    prev_attr = attr;
  }

  if (parser->ptr[0] == '/' && parser->ptr[1] == '>')
  {
    next(parser);
    next(parser);
    return true;
  }

  if (parser->ptr[0] != '>')
    return error(parser, "'>' expected");

  next(parser);

  XmlElement *prev_el = NULL;

  while (1)
  {
    if (!skip_spaces(parser))
      return false;

    if (parser->ptr[0] == '<' && parser->ptr[1] == '/')
    {
      if (!parse_closing_tag(parser, element))
        return false;
      break;
    }
    else if (parser->ptr[0] == '<')
    {
      XmlElement *el = os_arena_alloc(parser->file->arena, sizeof(XmlElement));

      if (element->text)
        return error(parser, "mixed type elements are not supported");

      if (!parse_element(parser, el))
        return false;

      el->parent = element;

      if (prev_el)
        prev_el->next = el;
      else
        element->elements = el;

      prev_el = el;
    }
    else
    {
      if (element->elements)
        return error(parser, "mixed type elements are not supported");

      element->text_loc = get_location(parser);
      element->text     = parse_text(parser);

      if (!element->text)
        return error(parser, "element text expected");
    }
  }

  return true;
}

//-----------------------------------------------------------------------------
XmlFile *xml_parse(char *text)
{
  XmlParser parser = {0};

  parser.file  = os_alloc(sizeof(XmlFile));
  parser.ptr   = text;
  parser.start = text;
  parser.line  = 1;

  parser.file->arena = os_arena_new(strlen(text) * 2);
  parser.file->root  = os_arena_alloc(parser.file->arena, sizeof(XmlElement));

  if (!skip_spaces(&parser))
    return parser.file;

  if (starts_with(&parser, "<?xml"))
  {
    if (!skip_until(&parser, "?>"))
      return parser.file;
  }

  if (!skip_spaces(&parser))
    return parser.file;

  if (starts_with(&parser, "<!DOCTYPE"))
  {
    if (!skip_until(&parser, ">"))
      return parser.file;
  }

  if (!parse_element(&parser, parser.file->root))
    return parser.file;

  if (!skip_spaces(&parser))
    return parser.file;

  if (parser.ptr[0] != 0)
    error(&parser, "junk at the end of the file");

  return parser.file;
}

//-----------------------------------------------------------------------------
void xml_free(XmlFile *file)
{
  os_arena_free(file->arena);
  os_free(file);
}

