// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023, Alex Taradov <alex@taradov.com>. All rights reserved.

#ifndef _SVD_H_
#define _SVD_H_

/*- Includes ----------------------------------------------------------------*/
#include "os_common.h"
#include "xml.h"

/*- Definitions -------------------------------------------------------------*/
enum
{
  SvdMessageType_Warning,
  SvdMessageType_Error,
};

enum
{
  SvdAccess_Undefined,
  SvdAccess_ReadOnly,
  SvdAccess_WriteOnly,
  SvdAccess_ReadWrite,
  SvdAccess_WriteOnce,
  SvdAccess_ReadWriteOnce,
};

enum
{
  SvdProtection_Undefined,
  SvdProtection_Secure,
  SvdProtection_NonSecure,
  SvdProtection_Privileged,
};

enum
{
  SvdEnumUsage_Undefined,
  SvdEnumUsage_Read,
  SvdEnumUsage_Write,
  SvdEnumUsage_ReadWrite,
};

enum
{
  SvdModWrite_Undefined,
  SvdModWrite_OneToClear,
  SvdModWrite_OneToSet,
  SvdModWrite_OneToToggle,
  SvdModWrite_ZeroToClear,
  SvdModWrite_ZeroToSet,
  SvdModWrite_ZeroToToggle,
  SvdModWrite_Clear,
  SvdModWrite_Set,
  SvdModWrite_Modify,
};

enum
{
  SvdReadAction_Undefined,
  SvdReadAction_Clear,
  SvdReadAction_Set,
  SvdReadAction_Modify,
  SvdReadAction_ModifyExt,
};

enum
{
  SvdWriteConstrType_Undefined,
  SvdWriteConstrType_WriteAsRead,
  SvdWriteConstrType_UseEnum,
  SvdWriteConstrType_Range,
};

enum
{
  SvdFieldType_None,
  SvdFieldType_Field,
  SvdFieldType_Template,
};

enum
{
  SvdItemType_None,
  SvdItemType_Register,
  SvdItemType_Cluster,
  SvdItemType_Template,
};

enum
{
  SvdLayoutType_None,
  SvdLayoutType_Union,
  SvdLayoutType_Struct,
  SvdLayoutType_Cluster,
  SvdLayoutType_Register,
  SvdLayoutType_UnionGroup,
};

/*- Types -------------------------------------------------------------------*/
typedef struct SvdMessage SvdMessage;
typedef struct SvdInterrupt SvdInterrupt;
typedef struct SvdEnumValue SvdEnumValue;
typedef struct SvdEnumeration SvdEnumeration;
typedef struct SvdField SvdField;
typedef struct SvdItem SvdItem;
typedef struct SvdLayout SvdLayout;
typedef struct SvdPeripheral SvdPeripheral;

typedef struct
{
  int      size;
  u32      increment;
  bool     sequential;
  char     **names;
} SvdDim;

typedef struct
{
  int      type;
  u32      min;
  u32      max;
} SvdWriteConstr;

typedef struct SvdInterrupt
{
  SvdInterrupt *next;
  char     *name;
  int      index;
  char     *description;
  SvdPeripheral *peripheral;
} SvdInterrupt;

typedef struct SvdEnumValue
{
  SvdEnumValue *next;
  char     *name;
  char     *description;
  u32      value;
  u32      mask;
  bool     is_default;
} SvdEnumValue;

typedef struct SvdEnumeration
{
  SvdEnumeration *derived;
  char     *name;
  char     *header_name;
  int      usage;
  SvdEnumValue *values;
} SvdEnumeration;

typedef struct SvdField
{
  SvdField *next;
  SvdField *derived;
  int      type;
  SvdField *ref;
  SvdDim   dim;
  char     *name;
  char     *description;
  int      lsb;
  int      msb;
  int      size;
  int      access;
  int      mod_write;
  SvdWriteConstr write_constr;
  int      read_action;
  SvdEnumeration *r_values;
  SvdEnumeration *w_values;
} SvdField;

typedef struct SvdItem
{
  SvdItem  *next;
  SvdItem  *derived;
  int      type;
  XmlLocation loc;
  bool     prefix_done;

  // Common
  SvdDim   dim;
  char     *name;
  char     *description;
  char     *alt_name;
  SvdItem  *alt;
  u32      offset;
  u32      size;
  int      access;
  int      protection;
  u32      reset_value;
  u32      reset_mask;
  SvdItem  *ref;

  // Register
  char     *display_name;
  char     *alt_group;
  char     *data_type;
  int      mod_write;
  SvdWriteConstr write_constr;
  int      read_action;
  SvdField *fields;

  // Cluster
  char     *struct_name;
  SvdItem  *items;
} SvdItem;

typedef struct SvdLayout
{
  SvdLayout *next;
  int      type;
  char     *name;
  char     *description;
  char     *struct_name;
  char     *derived;
  u32      dim;
  u32      increment;
  int      access;
  u32      offset;
  u32      size;
  u32      total_size;
  SvdField *fields;
  SvdLayout *items;
} SvdLayout;

typedef struct SvdPeripheral
{
  SvdPeripheral *next;
  SvdPeripheral *derived;
  SvdDim   dim;
  char     *name;
  char     *version;
  char     *description;
  char     *alt_per;
  char     *group_name;
  char     *prepend;
  char     *append;
  char     *struct_name;
  char     *disable_cond;
  u32      base_addr;

  int      size;
  int      access;
  int      protection;
  u32      reset_value;
  u32      reset_mask;

  SvdItem  registers;
  SvdLayout *layout;
} SvdPeripheral;

typedef struct
{
  bool     valid;
  char     *name;
  char     *revision;
  int      rev_r;
  int      rev_p;
  char     *endian;
  bool     mpu_present;
  bool     fpu_present;
  bool     fpu_dp;
  bool     dsp_present;
  bool     icache_present;
  bool     dcache_present;
  bool     itcm_present;
  bool     dtcm_present;
  bool     vtor_present;
  int      nvic_prio_bits;
  bool     vendor_systick;
  int      num_interrupts;
  int      sau_num_regions;
} SvdCpu;

typedef struct
{
  bool     valid;
  char     *vendor;
  char     *vendor_id;
  char     *name;
  char     *series;
  char     *version;
  char     *description;
  char     *license_text;
  SvdCpu   cpu;
  char     *header_filename;
  char     *header_prefix;
  int      address_unit_bits;
  int      width;
  SvdPeripheral *peripherals;
  SvdInterrupt  *interrupts;
} SvdDevice;

typedef struct SvdMessage
{
  SvdMessage *next;
  int        type;
  int        index;
  char       *text;
} SvdMessage;

typedef struct
{
  int      max_cluster_depth;
  int      max_dim_size;
  int      max_message_count;
  bool     skip_duplicate_messages;
  bool     convert_sequential_index_to_array;
  bool     ignore_reserved_elemnets;
  bool     remove_group_prefix;
  bool     generate_layout;
  bool     infer_register_groups;
} SvdOptions;

typedef struct
{
  SvdDevice  *device;
  SvdMessage *messages;
  int        error_count;
  int        warning_count;
  OsArena    *arena;
} SvdFile;

/*- Prototypes --------------------------------------------------------------*/
SvdFile *svd_parse(char *text, SvdOptions *options);
SvdOptions svd_default_options(void);
void svd_free(SvdFile *file);

#endif // _SVD_H_

