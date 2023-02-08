/*
 * Copyright 2023 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h> /* strtoimax */

#include <yubihsm.h>
#include <util_pkcs11.h>
#include "debug_p11.h"
/*
static bool str_to_uint16(const char *str, uint16_t *res)
{
  char *end;
  intmax_t val = strtoimax(str, &end, 16);
  if (val < 0 || val > UINT16_MAX || end == str || *end != '\0')
    return false;
  *res = (uint16_t) val;
  return true;
}
*/

static void print_byte_array(uint8_t *value, uint16_t value_len) {
  for (uint16_t i = 0; i < value_len; i++) {
    printf("%02x ", value[i]);
  }
  printf("\n");
}

static int read_file(char *filename, uint8_t *value, uint16_t *value_len) {
  FILE *fp;
  int c, l;

  fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "cannot open input file. Does it exist?\n");
    return -1;
  }
  l = 0;
  while ((c = getc(fp)) != EOF) {
    value[l++] = (uint8_t) c;
  }
  *value_len = l;
  fclose(fp);
  return 1;
}

static void print_meta_object(pkcs11_meta_object *meta_object) {
  if (meta_object->target_id == 0 && meta_object->target_type == 0) {
    printf(
      "No target original object is found. Is this really a meta_object?\n");
    return;
  }
  printf("   Original Object ID: 0x%02x\n", meta_object->target_id);
  printf("   Original Object Type: %d\n", meta_object->target_type);
  printf("   Original Object Sequence: %d\n", meta_object->target_sequence);

  printf("   CKA_ID len: %d\n", meta_object->cka_id.len);
  if (meta_object->cka_id.len > 0) {
    printf("   CKA_ID: ");
    print_byte_array(meta_object->cka_id.value, meta_object->cka_id.len);
  }

  printf("   CKA_LABEL len: %d\n", meta_object->cka_label.len);
  if (meta_object->cka_label.len > 0) {
    printf("   CKA_LABEL: ");
    print_byte_array(meta_object->cka_label.value, meta_object->cka_label.len);
  }

  printf("   Public key CKA_ID len: %d\n", meta_object->cka_id_pubkey.len);
  if (meta_object->cka_id_pubkey.len > 0) {
    printf("   Public key CKA_ID: ");
    print_byte_array(meta_object->cka_id_pubkey.value,
                     meta_object->cka_id_pubkey.len);
  }

  printf("   Public key CKA_LABEL len: %d\n",
         meta_object->cka_label_pubkey.len);
  if (meta_object->cka_label_pubkey.len > 0) {
    printf("   Public key CKA_LABEL: ");
    print_byte_array(meta_object->cka_label_pubkey.value,
                     meta_object->cka_label_pubkey.len);
  }
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: /path/to/opaque_value\n");
    fprintf(stderr, "The value of the opaque object should be obtained with "
                    "the command: \n");
    fprintf(stderr, "      > yubihsm-shell -a get-opaque -i <META_OBJECT ID> "
                    "--out /path/to/opaque_value --outformat=binary \n");
    exit(EXIT_FAILURE);
  }

  uint8_t meta_value[2048] = {0};
  uint16_t meta_value_len = sizeof(meta_value);
  int ret = read_file(argv[1], meta_value, &meta_value_len);
  if (ret != 1) {
    exit(EXIT_FAILURE);
  }

  pkcs11_meta_object mobj = {0};
  parse_meta_object(meta_value, meta_value_len, &mobj);
  print_meta_object(&mobj);
}
