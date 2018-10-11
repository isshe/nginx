/*
 * Copyright (c) 2013 Yaroslav Stavnichiy <yarosla@gmail.com>
 *
 * This file is part of NXJSON.
 *
 * NXJSON is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * NXJSON is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with NXJSON. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NGX_JSON_H
#define NGX_JSON_H

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum ngx_json_type {
  NX_JSON_NULL,    // this is null value
  NX_JSON_OBJECT,  // this is an object; properties can be found in child nodes
  NX_JSON_ARRAY,   // this is an array; items can be found in child nodes
  NX_JSON_STRING,  // this is a string; value can be found in text_value field
  NX_JSON_INTEGER, // this is an integer; value can be found in int_value field
  NX_JSON_DOUBLE,  // this is a double; value can be found in dbl_value field
  NX_JSON_BOOL     // this is a boolean; value can be found in int_value field
} ngx_json_type;

typedef struct ngx_json {
  ngx_json_type type;       // type of json node, see above
  const char* key;         // key of the property; for object's children only
  const char* text_value;  // text value of STRING node
  long long int_value;     // the value of INTEGER or BOOL node
  double dbl_value;        // the value of DOUBLE node
  int length;              // number of children of OBJECT or ARRAY
  struct ngx_json* child;   // points to first child
  struct ngx_json* next;    // points to next child
  struct ngx_json* last_child;
} ngx_json;

typedef int (*nx_json_unicode_encoder)(unsigned int codepoint, char* p, char** endp);

extern nx_json_unicode_encoder nx_json_unicode_to_utf8;

const ngx_json* ngx_json_parse(ngx_pool_t *pool, char* text, nx_json_unicode_encoder encoder);
const ngx_json* ngx_json_parse_utf8(ngx_pool_t *pool, char* text);
void ngx_json_free(ngx_pool_t *pool, const ngx_json* js);
const ngx_json* ngx_json_get(const ngx_json* json, const char* key); // get object's property by key
const ngx_json* ngx_json_item(const ngx_json* json, int idx); // get array element by index
void ngx_json_print(ngx_uint_t level, ngx_log_t *log, const ngx_json *json);

#ifdef  __cplusplus
}
#endif

#endif  /* NXJSON_H */
