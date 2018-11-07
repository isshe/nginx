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

// this file can be #included in your code
#ifndef NGX_JSON_C
#define NGX_JSON_C
/*
#ifdef  __cplusplus
extern "C" {
#endif
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>


#include <ngx_json.h>

// redefine NGX_JSON_CALLOC & NX_JSON_FREE to use custom allocator
#ifndef NGX_JSON_CALLOC
//#define NGX_JSON_CALLOC() calloc(1, sizeof(ngx_json))
//#define NX_JSON_FREE(json) free((void*)(json))
#define NGX_JSON_CALLOC(pool) ngx_palloc(pool, sizeof(ngx_json));
#define NX_JSON_FREE(pool, json) ngx_pfree(pool, (void*)json)
#endif

// redefine NGX_JSON_REPORT_ERROR to use custom error reporting
#ifndef NGX_JSON_REPORT_ERROR
//#define NGX_JSON_REPORT_ERROR(msg, p) fprintf(stderr, "NGX_JSON PARSE ERROR (%d): " msg " at %s\n", __LINE__, p)
#define NGX_JSON_REPORT_ERROR(msg, p) ngx_log_stderr(0, "NGX_JSON PARSE ERROR (%d): " msg " at %s\n", __LINE__, p)

#endif

#define IS_WHITESPACE(c) ((unsigned char)(c)<=(unsigned char)' ')

static const ngx_json dummy={ NX_JSON_NULL };

static ngx_json* ngx_create_json(ngx_pool_t *pool, ngx_json_type type, const char* key, ngx_json* parent) {
  ngx_json* js=NGX_JSON_CALLOC(pool);
  assert(js);
  js->type=type;
  js->key=key;
  js->text_value = NULL;
  js->int_value = 0;
  js->dbl_value = 0.0;
  js->child = NULL;
  js->next = NULL;
  js->last_child = NULL;
  if (!parent->last_child) {
    parent->child=parent->last_child=js;
  }
  else {
    parent->last_child->next=js;
    parent->last_child=js;
  }
  parent->length++;
  return js;
}

void ngx_json_free(ngx_pool_t *pool, const ngx_json* js) {
  
  ngx_json* p=js->child;
  ngx_json* p1;
  while (p) {
    p1=p->next;
    ngx_json_free(pool, p);
    p=p1;
  }
  NX_JSON_FREE(pool, js);
  
}

static int ngx_unicode_to_utf8(unsigned int codepoint, char* p, char** endp) {
  // code from http://stackoverflow.com/a/4609989/697313
  if (codepoint<0x80) *p++=codepoint;
  else if (codepoint<0x800) *p++=192+codepoint/64, *p++=128+codepoint%64;
  else if (codepoint-0xd800u<0x800) return 0; // surrogate must have been treated earlier
  else if (codepoint<0x10000) *p++=224+codepoint/4096, *p++=128+codepoint/64%64, *p++=128+codepoint%64;
  else if (codepoint<0x110000) *p++=240+codepoint/262144, *p++=128+codepoint/4096%64, *p++=128+codepoint/64%64, *p++=128+codepoint%64;
  else return 0; // error
  *endp=p;
  return 1;
}

nx_json_unicode_encoder nx_json_unicode_to_utf8=ngx_unicode_to_utf8;

static inline int hex_val(char c) {
  if (c>='0' && c<='9') return c-'0';
  if (c>='a' && c<='f') return c-'a'+10;
  if (c>='A' && c<='F') return c-'A'+10;
  return -1;
}

static char* unescape_string(char* s, char** end, nx_json_unicode_encoder encoder) {
  char* p=s;
  char* d=s;
  char c;
  while ((c=*p++)) {
    if (c=='"') {
      *d='\0';
      *end=p;
      return s;
    }
    else if (c=='\\') {
      switch (*p) {
        case '\\':
        case '/':
        case '"':
          *d++=*p++;
          break;
        case 'b':
          *d++='\b'; p++;
          break;
        case 'f':
          *d++='\f'; p++;
          break;
        case 'n':
          *d++='\n'; p++;
          break;
        case 'r':
          *d++='\r'; p++;
          break;
        case 't':
          *d++='\t'; p++;
          break;
        case 'u': // unicode
          if (!encoder) {
            // leave untouched
            *d++=c;
            break;
          }
          char* ps=p-1;
          int h1, h2, h3, h4;
          if ((h1=hex_val(p[1]))<0 || (h2=hex_val(p[2]))<0 || (h3=hex_val(p[3]))<0 || (h4=hex_val(p[4]))<0) {
            NGX_JSON_REPORT_ERROR("invalid unicode escape", p-1);
            return 0;
          }
          unsigned int codepoint=h1<<12|h2<<8|h3<<4|h4;
          if ((codepoint & 0xfc00)==0xd800) { // high surrogate; need one more unicode to succeed
            p+=6;
            if (p[-1]!='\\' || *p!='u' || (h1=hex_val(p[1]))<0 || (h2=hex_val(p[2]))<0 || (h3=hex_val(p[3]))<0 || (h4=hex_val(p[4]))<0) {
              NGX_JSON_REPORT_ERROR("invalid unicode surrogate", ps);
              return 0;
            }
            unsigned int codepoint2=h1<<12|h2<<8|h3<<4|h4;
            if ((codepoint2 & 0xfc00)!=0xdc00) {
              NGX_JSON_REPORT_ERROR("invalid unicode surrogate", ps);
              return 0;
            }
            codepoint=0x10000+((codepoint-0xd800)<<10)+(codepoint2-0xdc00);
          }
          if (!encoder(codepoint, d, &d)) {
            NGX_JSON_REPORT_ERROR("invalid codepoint", ps);
            return 0;
          }
          p+=5;
          break;
        default:
          // leave untouched
          *d++=c;
          break;
      }
    }
    else {
      *d++=c;
    }
  }
  NGX_JSON_REPORT_ERROR("no closing quote for string", s);
  return 0;
}

static char* skip_block_comment(char* p) {
  // assume p[-2]=='/' && p[-1]=='*'
  char* ps=p-2;
  if (!*p) {
    NGX_JSON_REPORT_ERROR("endless comment", ps);
    return 0;
  }
  REPEAT:
  p=strchr(p+1, '/');
  if (!p) {
    NGX_JSON_REPORT_ERROR("endless comment", ps);
    return 0;
  }
  if (p[-1]!='*') goto REPEAT;
  return p+1;
}

static char* ngx_parse_key(char** key, char* p, nx_json_unicode_encoder encoder) {
//static char* ngx_parse_key(const char** key, char* p, nx_json_unicode_encoder encoder) {
  // on '}' return with *p=='}'
  char c;
  while ((c=*p++)) {
    if (c=='"') {
      *key=unescape_string(p, &p, encoder);
      if (!*key) return 0; // propagate error
      while (*p && IS_WHITESPACE(*p)) p++;
      if (*p==':') return p+1;
      NGX_JSON_REPORT_ERROR("unexpected chars", p);
      return 0;
    }
    else if (IS_WHITESPACE(c) || c==',') {
      // continue
    }
    else if (c=='}') {
      return p-1;
    }
    else if (c=='/') {
      if (*p=='/') { // line comment
        char* ps=p-1;
        p=strchr(p+1, '\n');
        if (!p) {
          NGX_JSON_REPORT_ERROR("endless comment", ps);
          return 0; // error
        }
        p++;
      }
      else if (*p=='*') { // block comment
        p=skip_block_comment(p+1);
        if (!p) return 0;
      }
      else {
        NGX_JSON_REPORT_ERROR("unexpected chars", p-1);
        return 0; // error
      }
    }
    else {
      NGX_JSON_REPORT_ERROR("unexpected chars", p-1);
      return 0; // error
    }
  }
  NGX_JSON_REPORT_ERROR("unexpected chars", p-1);
  return 0; // error
}

static char* ngx_parse_value(ngx_pool_t *pool, ngx_json* parent, const char* key, char* p, nx_json_unicode_encoder encoder) {
  ngx_json* js;
  while (1) {
    switch (*p) {
      case '\0':
        NGX_JSON_REPORT_ERROR("unexpected end of text", p);
        return 0; // error
      case ' ': case '\t': case '\n': case '\r':
      case ',':
        // skip
        p++;
        break;
      case '{':
        js=ngx_create_json(pool, NX_JSON_OBJECT, key, parent);
        p++;
        while (1) {
          //const char* new_key;
          char* new_key = NULL;
          p=ngx_parse_key(&new_key, p, encoder);
          if (!p) return 0; // error
          if (*p=='}') return p+1; // end of object
          p=ngx_parse_value(pool, js, new_key, p, encoder);
          if (!p) return 0; // error
        }
      case '[':
        js=ngx_create_json(pool, NX_JSON_ARRAY, key, parent);
        p++;
        while (1) {
          p=ngx_parse_value(pool, js, 0, p, encoder);
          if (!p) return 0; // error
          if (*p==']') return p+1; // end of array
        }
      case ']':
        return p;
      case '"':
        p++;
        js=ngx_create_json(pool, NX_JSON_STRING, key, parent);
        js->text_value=unescape_string(p, &p, encoder);
        if (!js->text_value) return 0; // propagate error
        return p;
      case '-': case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        {
          js=ngx_create_json(pool, NX_JSON_INTEGER, key, parent);
          char* pe;
          js->int_value=strtoll(p, &pe, 0);
          if (pe==p || errno==ERANGE) {
            NGX_JSON_REPORT_ERROR("invalid number", p);
            return 0; // error
          }
          if (*pe=='.' || *pe=='e' || *pe=='E') { // double value
            js->type=NX_JSON_DOUBLE;
            js->dbl_value=strtod(p, &pe);
            if (pe==p || errno==ERANGE) {
              NGX_JSON_REPORT_ERROR("invalid number", p);
              return 0; // error
            }
          }
          else {
            js->dbl_value=js->int_value;
          }
          return pe;
        }
      case 't':
        if (!strncmp(p, "true", 4)) {
          js=ngx_create_json(pool, NX_JSON_BOOL, key, parent);
          js->int_value=1;
          return p+4;
        }
        NGX_JSON_REPORT_ERROR("unexpected chars", p);
        return 0; // error
      case 'f':
        if (!strncmp(p, "false", 5)) {
          js=ngx_create_json(pool, NX_JSON_BOOL, key, parent);
          js->int_value=0;
          return p+5;
        }
        NGX_JSON_REPORT_ERROR("unexpected chars", p);
        return 0; // error
      case 'n':
        if (!strncmp(p, "null", 4)) {
          ngx_create_json(pool, NX_JSON_NULL, key, parent);
          return p+4;
        }
        NGX_JSON_REPORT_ERROR("unexpected chars", p);
        return 0; // error
      case '/': // comment
        if (p[1]=='/') { // line comment
          char* ps=p;
          p=strchr(p+2, '\n');
          if (!p) {
            NGX_JSON_REPORT_ERROR("endless comment", ps);
            return 0; // error
          }
          p++;
        }
        else if (p[1]=='*') { // block comment
          p=skip_block_comment(p+2);
          if (!p) return 0;
        }
        else {
          NGX_JSON_REPORT_ERROR("unexpected chars", p);
          return 0; // error
        }
        break;
      default:
        NGX_JSON_REPORT_ERROR("unexpected chars", p);
        return 0; // error
    }
  }
}

const ngx_json* ngx_json_parse_utf8(ngx_pool_t *pool, char* text) {
  return ngx_json_parse(pool, text, ngx_unicode_to_utf8);
}

const ngx_json* ngx_json_parse(ngx_pool_t *pool, char* text, nx_json_unicode_encoder encoder) {
  ngx_json js={0};
  if (!ngx_parse_value(pool, &js, 0, text, encoder)) {
    if (js.child) ngx_json_free(pool, js.child);
    return 0;
  }
  return js.child;
}

const ngx_json* ngx_json_get(const ngx_json* json, const char* key) {
  if (!json || !key) return &dummy; // never return null
  ngx_json* js;
  for (js=json->child; js; js=js->next) {
    if (js->key && !strcmp(js->key, key)) return js;
  }
  return &dummy; // never return null
}

const ngx_json* ngx_json_item(const ngx_json* json, int idx) {
  if (!json) return &dummy; // never return null
  ngx_json* js;
  for (js=json->child; js; js=js->next) {
    if (!idx--) return js;
  }
  return &dummy; // never return null
}

static void do_ngx_json_print(ngx_uint_t level, ngx_log_t *log, const ngx_json *p)
{
    if (p) 
    {
      switch(p->type) {
        case NX_JSON_STRING:
          if (p->text_value) {
		  	ngx_log_debug2(level, log, 0, "%s:%s", p->key, p->text_value);
		  }
          break;
        case NX_JSON_INTEGER:
          ngx_log_debug2(level, log, 0, "%s:%d", p->key, p->int_value);
          break;
        case NX_JSON_DOUBLE:
          ngx_log_debug2(level, log, 0, "%s:%f", p->key, p->dbl_value);
          break;
        default:
          if (p->text_value) {
		  	ngx_log_debug2(level, log, 0, "%s:%s", p->key, p->text_value);
		  }
          break;
      }
  }
}

void ngx_json_print(ngx_uint_t level, ngx_log_t *log, const ngx_json *json)
{
  if (!json || !log) {
    return ;
  }
  ngx_json *p = json->child;
  ngx_json *p1;

  while(p) {
    p1 = p->next;
    do_ngx_json_print(level, log, p);
    ngx_json_print(level, log, p);
    p = p1;
  }
}

/*
#ifdef  __cplusplus
}
#endif
*/

#endif  /* NXJSON_C */
