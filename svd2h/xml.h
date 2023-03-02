// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

#ifndef _XML_H_
#define _XML_H_

/*- Includes ----------------------------------------------------------------*/
#include "os_common.h"

/*- Types -------------------------------------------------------------------*/
typedef struct XmlAttribute XmlAttribute;
typedef struct XmlElement XmlElement;

typedef struct
{
  int      line;
  int      column;
} XmlLocation;

typedef struct XmlAttribute
{
  XmlAttribute *next;
  XmlElement   *parent;
  char         *name;
  char         *value;
  XmlLocation  name_loc;
  XmlLocation  value_loc;
} XmlAttribute;

typedef struct XmlElement
{
  XmlElement   *next;
  XmlElement   *parent;
  char         *name;
  char         *text;
  XmlLocation  name_loc;
  XmlLocation  text_loc;
  XmlAttribute *attributes;
  XmlElement   *elements;
} XmlElement;

typedef struct
{
  XmlElement   *root;
  char         *error;
  OsArena      *arena;
} XmlFile;

/*- Prototypes --------------------------------------------------------------*/
XmlFile *xml_parse(char *text);
void xml_free(XmlFile *file);

#endif // _XML_H_

