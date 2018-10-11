
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_DAV_OFF             2


#define NGX_HTTP_DAV_NO_DEPTH        -3
#define NGX_HTTP_DAV_INVALID_DEPTH   -2
#define NGX_HTTP_DAV_INFINITY_DEPTH  -1


typedef struct {
    ngx_uint_t  methods;
    ngx_uint_t  access;
    ngx_uint_t  min_delete_depth;
    ngx_flag_t  create_full_put_path;
} ngx_http_dav_loc_conf_t;


typedef struct {
    ngx_str_t   path;
    size_t      len;
} ngx_http_dav_copy_ctx_t;


static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);

static void ngx_http_dav_put_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_path(ngx_http_request_t *r,
    ngx_str_t *path, ngx_uint_t dir);
static ngx_int_t ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path);

static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r,
    ngx_http_dav_loc_conf_t *dlcf);

static ngx_int_t ngx_http_dav_copy_move_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);
static ngx_int_t ngx_http_dav_copy_tree_file(ngx_tree_ctx_t *ctx,
    ngx_str_t *path);

static ngx_int_t ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt);
static ngx_int_t ngx_http_dav_error(ngx_log_t *log, ngx_err_t err,
    ngx_int_t not_found, char *failed, u_char *path);
static ngx_int_t ngx_http_dav_location(ngx_http_request_t *r, u_char *path);
static void *ngx_http_dav_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_dav_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
//static ngx_int_t ngx_http_dav_init(ngx_conf_t *cf);

// 子请求结束后的处理方法
static ngx_int_t ngx_http_dav_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);

// 父请求的回调方法
static void ngx_http_dav_post_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_subrequest_create(ngx_http_request_t *r, ngx_str_t *sub_uri);

// 获取destination，排除host部分，注意这个函数只是返回一个指针，里面的内容不能改！
static u_char *ngx_http_dav_destination_get(ngx_http_request_t *r, ngx_table_elt_t *dest);

// 生成子请求的URI
static ngx_str_t subrequest_uri_generate_by_dst(ngx_http_request_t *r,
                                                ngx_str_t *prefix,
                                                ngx_str_t *method,
                                                ngx_str_t *dst);

// 生成子请求的URI
static ngx_str_t subrequest_uri_generate_by_src_dst(ngx_http_request_t *r,
                                                    ngx_str_t *prefix, ngx_str_t *method,
                                                    ngx_str_t *src, ngx_str_t *dst);

// 获取destination，结果存在res_uri, 里面的内容不能修改！
static int destination_uri_string_get(ngx_http_request_t *r, ngx_str_t *res_uri);

static char *ngx_http_dav_deal_with(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    { ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("get"), NGX_HTTP_GET},
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_string("mkcol"), NGX_HTTP_MKCOL },
    { ngx_string("copy"), NGX_HTTP_COPY },
    { ngx_string("move"), NGX_HTTP_MOVE },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_dav_commands[] = {

    { ngx_string("dav_methods"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, methods),
      &ngx_http_dav_methods_mask },

    { ngx_string("create_full_put_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, create_full_put_path),
      NULL },

    { ngx_string("min_delete_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, min_delete_depth),
      NULL },

    { ngx_string("dav_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, access),
      NULL },

        { ngx_string("dav_deal_with"),
          NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_NOARGS,
          ngx_http_dav_deal_with,
          NGX_HTTP_LOC_CONF_OFFSET,
          0,
          NULL },
      ngx_null_command
};


static ngx_http_module_t  ngx_http_dav_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL, //ngx_http_dav_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_dav_create_loc_conf,          /* create location configuration */
    ngx_http_dav_merge_loc_conf            /* merge location configuration */
};

// 编译时就已经加入到ngx_modules全局数组中
ngx_module_t  ngx_http_dav_module = {
    NGX_MODULE_V1,
    &ngx_http_dav_module_ctx,              /* module context */
    ngx_http_dav_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_dav_get_handler(ngx_http_request_t *r)
{
   u_char                    *last, *location;
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "---isshe---: http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "---isshe---: http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        ngx_http_clear_location(r);

        r->headers_out.location = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {
            location = path.data + clcf->root.len;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                ngx_http_clear_location(r);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        ngx_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif
    /*
    if (r->method == NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }


    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    */

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

// 子请求结束后的处理方法
static ngx_int_t
ngx_http_dav_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_subrequest_post_handler----rc = %d\n", rc);
    /* // 和后端的交互正常以后把这里开了
    if (rc != NGX_HTTP_OK) {
        return NGX_OK;
    }
    */

    // 解析json示例

    char *str = "{\"status\":1,\"data\":{\"src\":\"src\",\"dst\":\"dst\"}}";
    char *json_str = (char *)ngx_palloc(r->pool, strlen(str) + 1); //(char *)malloc(strlen(str) + 1);
    ngx_memcpy(json_str, str, strlen(str));
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "%s\n", json_str);
    //const nx_json* json=nx_json_parse_utf8(json_str);
    const ngx_json* json=ngx_json_parse(r->pool, json_str, NULL);
    if (!json) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "json parse failed.");
        //return 0;
    }
    ngx_json_print(NGX_LOG_DEBUG_HTTP, r->connection->log, json);
    ngx_pfree(r->pool, json_str);

    ngx_http_request_t *pr = r->parent;

    switch (pr->method) {
        /*
        case NGX_HTTP_GET:
        {
            rc = ngx_http_dav_get_handler(pr);
            break;
        }
        */

        case NGX_HTTP_PUT:
            if (pr->uri.data[pr->uri.len - 1] == '/') {
                ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0,
                              "cannot PUT to a collection");

                return NGX_HTTP_CONFLICT;
            }
            
            /*
            if (pr->headers_in.content_range) {
                ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0,
                              "PUT with range is unsupported");
                return NGX_HTTP_NOT_IMPLEMENTED;
            }
            */

            pr->request_body_in_file_only = 1;
            pr->request_body_in_persistent_file = 1;
            pr->request_body_in_clean_file = 1;
            pr->request_body_file_group_access = 1;
            pr->request_body_file_log_level = 0;

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_post_handler: before ngx_http_read_client_request_body---\n");
            rc = ngx_http_read_client_request_body(pr, ngx_http_dav_put_handler);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_post_handler: behind ngx_http_read_client_request_body---\n");
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                break;
                //return rc;
            }
            pr->headers_out.status = rc;
            //pr->write_event_handler = ngx_http_dav_post_handler;
            return NGX_DONE;
            //rc = NGX_DONE;
            //break;
        /*
        case NGX_HTTP_DELETE:
        {
            rc = ngx_http_dav_delete_handler(pr);
            break;
        }

        case NGX_HTTP_MKCOL:
            rc = ngx_http_dav_mkcol_handler(pr, dlcf);
            break;

        case NGX_HTTP_COPY:
            rc = ngx_http_dav_copy_move_handler(pr);
            break;

        case NGX_HTTP_MOVE:
            rc = ngx_http_dav_copy_move_handler(pr);
            break;
            */
    }

    pr->headers_out.status = rc;
    pr->write_event_handler = ngx_http_dav_post_handler;
    //pr->headers_out = r->headers_out;       // 直接把子请求的响应返回去
    return NGX_OK;
}

// 父请求的回调方法
static void
ngx_http_dav_post_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = r->headers_out.status;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_post_handler: r->headers_out.status = %d, method = %d----\n", r->headers_out.status, r->method);
    //r->headers_out.status = NGX_HTTP_NO_CONTENT;
    //r->header_only = 1;
    //ngx_int_t ret = ngx_http_send_header(r);
    //ngx_http_send_header(r);

    /*
    int body_len = 10;
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, body_len);
    ngx_snprintf(buf->pos, body_len, "%s\n", "isshe");
    buf->last = buf->pos + body_len;
    buf->last_buf = 1;
    ngx_chain_t out;
    out.buf = buf;
    out.next = NULL;
    static ngx_str_t type = ngx_string("text/plain; charset=UTF-8");
    r->headers_out.content_type = type;
    r->headers_out.status = NGX_HTTP_OK;
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
    */

    //ngx_http_send_header(r);

    //ngx_http_output_filter(r, &out); //r->request_body->bufs);
    //ngx_http_finalize_request(r, ret);
    //ngx_http_finalize_request(r, r->headers_out.status);

    // get 放回父请求，因为子请求无法处理

    switch (r->method) {
        case NGX_HTTP_GET:
        {
            rc = ngx_http_dav_get_handler(r);
            break;
        }
        case NGX_HTTP_DELETE:
        {
            rc = ngx_http_dav_delete_handler(r);
            break;
        }

        case NGX_HTTP_MKCOL:
        {
            ngx_http_dav_loc_conf_t  *dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
            rc = ngx_http_dav_mkcol_handler(r, dlcf);
            break;
        }

        case NGX_HTTP_COPY:
            rc = ngx_http_dav_copy_move_handler(r);
            break;

        case NGX_HTTP_MOVE:
            rc = ngx_http_dav_copy_move_handler(r);
            break;
    }
    //if (r->method != NGX_HTTP_PUT){
    //    ngx_http_send_header(r);
        ngx_http_finalize_request(r, rc);
    //}
}

static ngx_int_t
ngx_http_dav_subrequest_create(ngx_http_request_t *r, ngx_str_t *sub_uri)
{
    if (!r || !sub_uri || sub_uri->len == 0 || sub_uri->data == NULL) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_subrequest_create----\n");
    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (!psr) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 设置子请求的回调
    psr->handler = ngx_http_dav_subrequest_post_handler;

    //ngx_str_t sub_uri = ngx_string("/index");
    ngx_http_request_t *sr;

    //return ngx_http_subrequest(r, sub_uri, NULL, &sr, psr, 0); // NGX_HTTP_SUBREQUEST_IN_MEMORY);
    return ngx_http_subrequest(r, sub_uri, NULL, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
}


static ngx_str_t
subrequest_uri_generate_by_dst(ngx_http_request_t *r,
                                ngx_str_t *prefix,
                                ngx_str_t *method,
                                ngx_str_t *dst)
{
    ngx_str_t dst_prefix = ngx_string("&dst=");
    ngx_str_t user_prefix = ngx_string("&user=");
    ngx_str_t uri;
    uri.len = prefix->len + method->len + dst_prefix.len
                + dst->len + user_prefix.len + r->headers_in.user.len;
    uri.data = ngx_palloc(r->pool, uri.len);    // + 1
    if (uri.data) {
        ngx_snprintf(uri.data, uri.len, "%V%V%V%V%V%V", prefix, method,
                    &user_prefix, &r->headers_in.user, &dst_prefix, dst);
        //uri.data[uri.len] = '\0';
    }
    return uri;
}


static ngx_str_t
subrequest_uri_generate_by_src_dst(ngx_http_request_t *r,
                                    ngx_str_t *prefix,
                                    ngx_str_t *method,
                                    ngx_str_t *src,
                                    ngx_str_t *dst)
{
    ngx_str_t src_prefix = ngx_string("&src=");
    ngx_str_t dst_prefix = ngx_string("&dst=");
    ngx_str_t user_prefix = ngx_string("&user=");

    ngx_str_t uri;
    uri.len = prefix->len + method->len + src->len + dst->len
                + src_prefix.len + dst_prefix.len + user_prefix.len
                + r->headers_in.user.len;
    uri.data = ngx_palloc(r->pool, uri.len); // + 1
    if (uri.data) {
        ngx_snprintf(uri.data, uri.len, "%V%V%V%V%V%V%V%V", prefix, method, &user_prefix,
                    &r->headers_in.user, &src_prefix, src, &dst_prefix, dst);
        //uri.data[uri.len] = '\0';
    }
    return uri;
}

static int
destination_uri_string_get(ngx_http_request_t *r, ngx_str_t *res_uri)
{
    u_char *last, *p;

    ngx_table_elt_t *dest = r->headers_in.destination;
    if (dest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return NGX_ERROR;
        //return NGX_HTTP_BAD_REQUEST;
    }
    p = ngx_http_dav_destination_get(r, dest);
    if (!p) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Destination\" header: \"%V\"",
                      &dest->value);
        return NGX_ERROR;
        //return NGX_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;
    res_uri->len = last - p;
    res_uri->data = p;

    return NGX_OK;
}

// 具体的文件操作，放到子请求返回的处理函数中进行
static ngx_int_t
ngx_http_dav_handler(ngx_http_request_t *r)
{
    ngx_int_t                 rc;
    ngx_http_dav_loc_conf_t  *dlcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "-----isshe-----: int ngx_http_dav_handler----\n");

    rc = ngx_http_auth_basic_user(r);

    // 没有用户信息或者是解析错误，都返回错误
    if (rc == NGX_DECLINED || rc == NGX_ERROR) {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "-----isshe-----: r->uri = %d:%s----\n", r->uri.len, r->uri.data);

    if (r->headers_in.authorization && r->headers_in.authorization->value.len > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_post_handler: user 1= %s---\n", r->headers_in.authorization->value.data);
    }

    if (r->headers_in.user.len > 0) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "-----isshe-----: in ngx_http_dav_post_handler: user 2= %s---\n", r->headers_in.user.data);
    }

    // 提前校验
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!(r->method & dlcf->methods)) {
        return NGX_DECLINED;
    }

    ngx_str_t sub_uri;
    sub_uri.data = NULL;
    sub_uri.len = 0;
    ngx_str_t sub_prefix_update = ngx_string("/v1/admin/api/webdavd_update?method=");
    ngx_str_t sub_prefix_shared = ngx_string("/v1/admin/api/webdavd_shared?method=");
    // 以下准备子请求的URI
    switch (r->method) {
        case NGX_HTTP_GET:
        {
            ngx_str_t sub_method = ngx_string("get");
            sub_uri = subrequest_uri_generate_by_dst(r, &sub_prefix_shared, &sub_method, &r->uri);
            break;
        }
        case NGX_HTTP_PUT:
        {
            // 无法上传目录
            if (r->uri.data[r->uri.len - 1] == '/') {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "cannot PUT to a collection");
                return NGX_HTTP_CONFLICT;
            }
            /*
            if (r->headers_in.content_range) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "PUT with range is unsupported");
                return NGX_HTTP_NOT_IMPLEMENTED;
            }

            r->request_body_in_file_only = 1;
            r->request_body_in_persistent_file = 1;
            r->request_body_in_clean_file = 1;
            r->request_body_file_group_access = 1;
            r->request_body_file_log_level = 0;
            */
            // 格式化 sub_uri
            ngx_str_t sub_method = ngx_string("put");
            sub_uri = subrequest_uri_generate_by_dst(r, &sub_prefix_update, &sub_method, &r->uri);
            break;
        }
        case NGX_HTTP_DELETE:
        {
            // 格式化 sub_uri
            ngx_str_t sub_method = ngx_string("delete");
            sub_uri = subrequest_uri_generate_by_dst(r, &sub_prefix_update, &sub_method, &r->uri);
            break;
        }

        case NGX_HTTP_MKCOL:
        {
            // 格式化 sub_uri
            ngx_str_t sub_method = ngx_string("mkcol");
            sub_uri = subrequest_uri_generate_by_dst(r, &sub_prefix_update, &sub_method, &r->uri);
            break;
        }
        case NGX_HTTP_COPY:
        {
            ngx_str_t duri;
            if (destination_uri_string_get(r, &duri) != NGX_OK) {
                return NGX_HTTP_BAD_REQUEST;
            }
            // 格式化 sub_uri
            ngx_str_t sub_method = ngx_string("copy");
            sub_uri = subrequest_uri_generate_by_src_dst(r, &sub_prefix_update, &sub_method, &r->uri, &duri);
            break;
        }
        case NGX_HTTP_MOVE:
        {
            ngx_str_t duri;
            if (destination_uri_string_get(r, &duri) != NGX_OK) {
                return NGX_HTTP_BAD_REQUEST;
            }
            // 格式化 sub_uri
            ngx_str_t sub_method = ngx_string("move");
            sub_uri = subrequest_uri_generate_by_src_dst(r, &sub_prefix_update, &sub_method, &r->uri, &duri);
            break;
        }
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "-----isshe-----: method = %d, sub_uri = %d:%s----\n", r->method, sub_uri.len, sub_uri.data);

    if (sub_uri.len == 0 || !sub_uri.data) {
        return NGX_DECLINED;
    }

    rc = ngx_http_dav_subrequest_create(r, &sub_uri);
    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }

    // 如果是OK，就证明子请求已经创建, 接下来一定要返回NGX_DONE
    return NGX_DONE;
}


static void
ngx_http_dav_put_handler(ngx_http_request_t *r)
{
    size_t                    root;
    time_t                    date;
    ngx_str_t                *temp, path;
    ngx_uint_t                status;
    ngx_file_info_t           fi;
    ngx_ext_rename_file_t     ext;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "PUT request body is unavailable");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (r->request_body->temp_file == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "PUT request body must be in a file");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    path.len--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http put filename: \"%s\"", path.data);

    temp = &r->request_body->temp_file->file.name;

    if (ngx_file_info(path.data, &fi) == NGX_FILE_ERROR) {
        status = NGX_HTTP_CREATED;

    } else {
        status = NGX_HTTP_NO_CONTENT;

        if (ngx_is_dir(&fi)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                          "\"%s\" could not be created", path.data);

            if (ngx_delete_file(temp->data) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                              ngx_delete_file_n " \"%s\" failed",
                              temp->data);
            }

            ngx_http_finalize_request(r, NGX_HTTP_CONFLICT);
            return;
        }
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    ext.access = dlcf->access;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = dlcf->create_full_put_path;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (r->headers_in.date) {
        date = ngx_parse_http_time(r->headers_in.date->value.data,
                                   r->headers_in.date->value.len);

        if (date != NGX_ERROR) {
            ext.time = date;
            ext.fd = r->request_body->temp_file->file.fd;
        }
    }

    if (ngx_ext_rename_file(temp, &path, &ext) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (status == NGX_HTTP_CREATED) {
        if (ngx_http_dav_location(r, path.data) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
    return;
}


static ngx_int_t
ngx_http_dav_delete_handler(ngx_http_request_t *r)
{
    size_t                    root;
    ngx_err_t                 err;
    ngx_int_t                 rc, depth;
    ngx_uint_t                i, d, dir;
    ngx_str_t                 path;
    ngx_file_info_t           fi;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "DELETE with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    if (dlcf->min_delete_depth) {
        d = 0;

        for (i = 0; i < r->uri.len; /* void */) {
            if (r->uri.data[i++] == '/') {
                if (++d >= dlcf->min_delete_depth && i < r->uri.len) {
                    goto ok;
                }
            }
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "insufficient URI depth:%i to DELETE", d);
        return NGX_HTTP_CONFLICT;
    }

ok:

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http delete filename: \"%s\"", path.data);

    if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
        err = ngx_errno;

        rc = (err == NGX_ENOTDIR) ? NGX_HTTP_CONFLICT : NGX_HTTP_NOT_FOUND;

        return ngx_http_dav_error(r->connection->log, err,
                                  rc, ngx_link_info_n, path.data);
    }

    if (ngx_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                          "DELETE \"%s\" failed", path.data);
            return NGX_HTTP_CONFLICT;
        }

        depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);

        if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        path.len -= 2;  /* omit "/\0" */

        dir = 1;

    } else {

        /*
         * we do not need to test (r->uri.data[r->uri.len - 1] == '/')
         * because ngx_link_info("/file/") returned NGX_ENOTDIR above
         */

        depth = ngx_http_dav_depth(r, 0);

        if (depth != 0 && depth != NGX_HTTP_DAV_INFINITY_DEPTH) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be 0 or infinity");
            return NGX_HTTP_BAD_REQUEST;
        }

        dir = 0;
    }

    rc = ngx_http_dav_delete_path(r, &path, dir);

    if (rc == NGX_OK) {
        return NGX_HTTP_NO_CONTENT;
    }

    return rc;
}


static ngx_int_t
ngx_http_dav_delete_path(ngx_http_request_t *r, ngx_str_t *path, ngx_uint_t dir)
{
    char            *failed;
    ngx_tree_ctx_t   tree;

    if (dir) {

        tree.init_handler = NULL;
        tree.file_handler = ngx_http_dav_delete_file;
        tree.pre_tree_handler = ngx_http_dav_noop;
        tree.post_tree_handler = ngx_http_dav_delete_dir;
        tree.spec_handler = ngx_http_dav_delete_file;
        tree.data = NULL;
        tree.alloc = 0;
        tree.log = r->connection->log;

        /* TODO: 207 */

        if (ngx_walk_tree(&tree, path) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (ngx_delete_dir(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_dir_n;

    } else {

        if (ngx_delete_file(path->data) != NGX_FILE_ERROR) {
            return NGX_OK;
        }

        failed = ngx_delete_file_n;
    }

    return ngx_http_dav_error(r->connection->log, ngx_errno,
                              NGX_HTTP_NOT_FOUND, failed, path->data);
}


static ngx_int_t
ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete dir: \"%s\"", path->data);

    if (ngx_delete_dir(path->data) == NGX_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_dir_n,
                                  path->data);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http delete file: \"%s\"", path->data);

    if (ngx_delete_file(path->data) == NGX_FILE_ERROR) {

        /* TODO: add to 207 */

        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_delete_file_n,
                                  path->data);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_mkcol_handler(ngx_http_request_t *r, ngx_http_dav_loc_conf_t *dlcf)
{
    u_char    *p;
    size_t     root;
    ngx_str_t  path;

    if (r->headers_in.content_length_n > 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MKCOL with body is unsupported");
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    if (r->uri.data[r->uri.len - 1] != '/') {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "MKCOL can create a collection only");
        return NGX_HTTP_CONFLICT;
    }

    p = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    *(p - 1) = '\0';
    r->uri.len--;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http mkcol path: \"%s\"", path.data);

    if (ngx_create_dir(path.data, ngx_dir_access(dlcf->access))
        != NGX_FILE_ERROR)
    {
        if (ngx_http_dav_location(r, path.data) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return NGX_HTTP_CREATED;
    }

    return ngx_http_dav_error(r->connection->log, ngx_errno,
                              NGX_HTTP_CONFLICT, ngx_create_dir_n, path.data);
}

static u_char *
ngx_http_dav_destination_get(ngx_http_request_t *r, ngx_table_elt_t *dest)
{
    //ngx_table_elt_t *dest;
    u_char *p, *last, *host;
    size_t len;

    /*
    dest = r->headers_in.destination;
    if (dest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return NULL;
    }
     */

    p = dest->value.data;
    /* there is always '\0' even after empty header value */
    if (p[0] == '/') {
        return p;
        //last = p + dest->value.len;
        //goto destination_done;
    }

    len = r->headers_in.server.len;
    if (len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Host\" header");
        return NULL;
    }

#if (NGX_HTTP_SSL)

    if (r->connection->ssl) {
        if (ngx_strncmp(dest->value.data, "https://", sizeof("https://") - 1)
            != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Destination\" header: \"%V\"",
                  &dest->value);
            return NULL;
            //goto invalid_destination;
        }

        host = dest->value.data + sizeof("https://") - 1;

    } else
#endif
    {
        if (ngx_strncmp(dest->value.data, "http://", sizeof("http://") - 1) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid \"Destination\" header: \"%V\"",
                          &dest->value);
            return NULL;
            //goto invalid_destination;
        }

        host = dest->value.data + sizeof("http://") - 1;
    }

    if (ngx_strncmp(host, r->headers_in.server.data, len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "\"Destination\" URI \"%V\" is handled by "
                      "different repository than the source URI",
                      &dest->value);
        return NULL;
    }

    last = dest->value.data + dest->value.len;
    for (p = host + len; p < last; p++) {
        if (*p == '/') {
            return p;
            //goto destination_done;
        }
    }

    return NULL;
}

static ngx_int_t
ngx_http_dav_copy_move_handler(ngx_http_request_t *r)
{
    u_char                   *p, *last, ch; // *host,
    size_t                    root; // len
    ngx_err_t                 err;
    ngx_int_t                 rc, depth;
    ngx_uint_t                overwrite, slash, dir, flags;
    ngx_str_t                 path, uri, duri, args;
    ngx_tree_ctx_t            tree;
    ngx_copy_file_t           cf;
    ngx_file_info_t           fi;
    ngx_table_elt_t          *dest, *over;
    ngx_ext_rename_file_t     ext;
    ngx_http_dav_copy_ctx_t   copy;
    ngx_http_dav_loc_conf_t  *dlcf;

    if (r->headers_in.content_length_n > 0) {
        return NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    dest = r->headers_in.destination;
    if (dest == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent no \"Destination\" header");
        return NGX_HTTP_BAD_REQUEST;
    }

    p = ngx_http_dav_destination_get(r, dest);
    if (!p) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Destination\" header: \"%V\"",
                      &dest->value);
        return NGX_HTTP_BAD_REQUEST;
    }

    last = dest->value.data + dest->value.len;
    duri.len = last - p;
    duri.data = p;
    flags = NGX_HTTP_LOG_UNSAFE;

    if (ngx_http_parse_unsafe_uri(r, &duri, &args, &flags) != NGX_OK) {
        //goto invalid_destination;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Destination\" header: \"%V\"",
                      &dest->value);
        return NGX_HTTP_BAD_REQUEST;
    }

    if ((r->uri.data[r->uri.len - 1] == '/' && *(last - 1) != '/')
        || (r->uri.data[r->uri.len - 1] != '/' && *(last - 1) == '/'))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "both URI \"%V\" and \"Destination\" URI \"%V\" "
                      "should be either collections or non-collections",
                      &r->uri, &dest->value);
        return NGX_HTTP_CONFLICT;
    }

    depth = ngx_http_dav_depth(r, NGX_HTTP_DAV_INFINITY_DEPTH);

    if (depth != NGX_HTTP_DAV_INFINITY_DEPTH) {

        if (r->method == NGX_HTTP_COPY) {
            if (depth != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "\"Depth\" header must be 0 or infinity");
                return NGX_HTTP_BAD_REQUEST;
            }

        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"Depth\" header must be infinity");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    over = r->headers_in.overwrite;

    if (over) {
        if (over->value.len == 1) {
            ch = over->value.data[0];

            if (ch == 'T' || ch == 't') {
                overwrite = 1;
                goto overwrite_done;
            }

            if (ch == 'F' || ch == 'f') {
                overwrite = 0;
                goto overwrite_done;
            }

        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "client sent invalid \"Overwrite\" header: \"%V\"",
                      &over->value);
        return NGX_HTTP_BAD_REQUEST;
    }

    overwrite = 1;

overwrite_done:

    if (ngx_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy from: \"%s\"", path.data);

    uri = r->uri;
    r->uri = duri;

    if (ngx_http_map_uri_to_path(r, &copy.path, &root, 0) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->uri = uri;

    copy.path.len--;  /* omit "\0" */

    if (copy.path.data[copy.path.len - 1] == '/') {
        slash = 1;
        copy.path.len--;
        copy.path.data[copy.path.len] = '\0';

    } else {
        slash = 0;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy to: \"%s\"", copy.path.data);

    if (ngx_link_info(copy.path.data, &fi) == NGX_FILE_ERROR) {
        err = ngx_errno;

        if (err != NGX_ENOENT) {
            return ngx_http_dav_error(r->connection->log, err,
                                      NGX_HTTP_NOT_FOUND, ngx_link_info_n,
                                      copy.path.data);
        }

        /* destination does not exist */

        overwrite = 0;
        dir = 0;

    } else {

        /* destination exists */

        if (ngx_is_dir(&fi) && !slash) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"%V\" could not be %Ved to collection \"%V\"",
                          &r->uri, &r->method_name, &dest->value);
            return NGX_HTTP_CONFLICT;
        }

        if (!overwrite) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EEXIST,
                          "\"%s\" could not be created", copy.path.data);
            return NGX_HTTP_PRECONDITION_FAILED;
        }

        dir = ngx_is_dir(&fi);
    }

    if (ngx_link_info(path.data, &fi) == NGX_FILE_ERROR) {
        return ngx_http_dav_error(r->connection->log, ngx_errno,
                                  NGX_HTTP_NOT_FOUND, ngx_link_info_n,
                                  path.data);
    }

    if (ngx_is_dir(&fi)) {

        if (r->uri.data[r->uri.len - 1] != '/') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "\"%V\" is collection", &r->uri);
            return NGX_HTTP_BAD_REQUEST;
        }

        if (overwrite) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http delete: \"%s\"", copy.path.data);

            rc = ngx_http_dav_delete_path(r, &copy.path, dir);

            if (rc != NGX_OK) {
                return rc;
            }
        }
    }

    if (ngx_is_dir(&fi)) {

        path.len -= 2;  /* omit "/\0" */

        if (r->method == NGX_HTTP_MOVE) {
            if (ngx_rename_file(path.data, copy.path.data) != NGX_FILE_ERROR) {
                return NGX_HTTP_CREATED;
            }
        }

        if (ngx_create_dir(copy.path.data, ngx_file_access(&fi))
            == NGX_FILE_ERROR)
        {
            return ngx_http_dav_error(r->connection->log, ngx_errno,
                                      NGX_HTTP_NOT_FOUND,
                                      ngx_create_dir_n, copy.path.data);
        }

        copy.len = path.len;

        tree.init_handler = NULL;
        tree.file_handler = ngx_http_dav_copy_tree_file;
        tree.pre_tree_handler = ngx_http_dav_copy_dir;
        tree.post_tree_handler = ngx_http_dav_copy_dir_time;
        tree.spec_handler = ngx_http_dav_noop;
        tree.data = &copy;
        tree.alloc = 0;
        tree.log = r->connection->log;

        if (ngx_walk_tree(&tree, &path) == NGX_OK) {

            if (r->method == NGX_HTTP_MOVE) {
                rc = ngx_http_dav_delete_path(r, &path, 1);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            return NGX_HTTP_CREATED;
        }

    } else {

        if (r->method == NGX_HTTP_MOVE) {

            dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

            ext.access = 0;
            ext.path_access = dlcf->access;
            ext.time = -1;
            ext.create_path = 1;
            ext.delete_file = 0;
            ext.log = r->connection->log;

            if (ngx_ext_rename_file(&path, &copy.path, &ext) == NGX_OK) {
                return NGX_HTTP_NO_CONTENT;
            }

            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        cf.size = ngx_file_size(&fi);
        cf.buf_size = 0;
        cf.access = ngx_file_access(&fi);
        cf.time = ngx_file_mtime(&fi);
        cf.log = r->connection->log;

        if (ngx_copy_file(path.data, copy.path.data, &cf) == NGX_OK) {
            return NGX_HTTP_NO_CONTENT;
        }
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}


static ngx_int_t
ngx_http_dav_copy_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir to: \"%s\"", dir);

    if (ngx_create_dir(dir, ngx_dir_access(ctx->access)) == NGX_FILE_ERROR) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_create_dir_n,
                                  dir);
    }

    ngx_free(dir);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_copy_dir_time(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *dir;
    size_t                    len;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    dir = ngx_alloc(len + 1, ctx->log);
    if (dir == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(dir, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy dir time to: \"%s\"", dir);

#if (NGX_WIN32)
    {
    ngx_fd_t  fd;

    fd = ngx_open_file(dir, NGX_FILE_RDWR, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(ctx->log, ngx_errno, 0, ngx_open_file_n, dir);
        goto failed;
    }

    if (ngx_set_file_time(NULL, fd, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_set_file_time_n " \"%s\" failed", dir);
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", dir);
    }
    }

failed:

#else

    if (ngx_set_file_time(dir, 0, ctx->mtime) != NGX_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_errno,
                      ngx_set_file_time_n " \"%s\" failed", dir);
    }

#endif

    ngx_free(dir);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_copy_tree_file(ngx_tree_ctx_t *ctx, ngx_str_t *path)
{
    u_char                   *p, *file;
    size_t                    len;
    ngx_copy_file_t           cf;
    ngx_http_dav_copy_ctx_t  *copy;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file: \"%s\"", path->data);

    copy = ctx->data;

    len = copy->path.len + path->len;

    file = ngx_alloc(len + 1, ctx->log);
    if (file == NULL) {
        return NGX_ABORT;
    }

    p = ngx_cpymem(file, copy->path.data, copy->path.len);
    (void) ngx_cpystrn(p, path->data + copy->len, path->len - copy->len + 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                   "http copy file to: \"%s\"", file);

    cf.size = ctx->size;
    cf.buf_size = 0;
    cf.access = ctx->access;
    cf.time = ctx->mtime;
    cf.log = ctx->log;

    (void) ngx_copy_file(path->data, file, &cf);

    ngx_free(file);

    return NGX_OK;
}


static ngx_int_t
ngx_http_dav_depth(ngx_http_request_t *r, ngx_int_t dflt)
{
    ngx_table_elt_t  *depth;

    depth = r->headers_in.depth;

    if (depth == NULL) {
        return dflt;
    }

    if (depth->value.len == 1) {

        if (depth->value.data[0] == '0') {
            return 0;
        }

        if (depth->value.data[0] == '1') {
            return 1;
        }

    } else {

        if (depth->value.len == sizeof("infinity") - 1
            && ngx_strcmp(depth->value.data, "infinity") == 0)
        {
            return NGX_HTTP_DAV_INFINITY_DEPTH;
        }
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "client sent invalid \"Depth\" header: \"%V\"",
                  &depth->value);

    return NGX_HTTP_DAV_INVALID_DEPTH;
}


static ngx_int_t
ngx_http_dav_error(ngx_log_t *log, ngx_err_t err, ngx_int_t not_found,
    char *failed, u_char *path)
{
    ngx_int_t   rc;
    ngx_uint_t  level;

    if (err == NGX_ENOENT || err == NGX_ENOTDIR || err == NGX_ENAMETOOLONG) {
        level = NGX_LOG_ERR;
        rc = not_found;

    } else if (err == NGX_EACCES || err == NGX_EPERM) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_FORBIDDEN;

    } else if (err == NGX_EEXIST) {
        level = NGX_LOG_ERR;
        rc = NGX_HTTP_NOT_ALLOWED;

    } else if (err == NGX_ENOSPC) {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INSUFFICIENT_STORAGE;

    } else {
        level = NGX_LOG_CRIT;
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(level, log, err, "%s \"%s\" failed", failed, path);

    return rc;
}


static ngx_int_t
ngx_http_dav_location(ngx_http_request_t *r, u_char *path)
{
    u_char                    *location;
    ngx_http_core_loc_conf_t  *clcf;

    r->headers_out.location = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.location == NULL) {
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (!clcf->alias && clcf->root_lengths == NULL) {
        location = path + clcf->root.len;

    } else {
        location = ngx_pnalloc(r->pool, r->uri.len);
        if (location == NULL) {
            ngx_http_clear_location(r);
            return NGX_ERROR;
        }

        ngx_memcpy(location, r->uri.data, r->uri.len);
    }

    r->headers_out.location->hash = 1;
    ngx_str_set(&r->headers_out.location->key, "Location");
    r->headers_out.location->value.len = r->uri.len;
    r->headers_out.location->value.data = location;

    return NGX_OK;
}


static void *
ngx_http_dav_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_dav_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_dav_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->methods = 0;
     */

    conf->min_delete_depth = NGX_CONF_UNSET_UINT;
    conf->access = NGX_CONF_UNSET_UINT;
    conf->create_full_put_path = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t  *prev = parent;
    ngx_http_dav_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET|NGX_HTTP_DAV_OFF));

    ngx_conf_merge_uint_value(conf->min_delete_depth,
                         prev->min_delete_depth, 0);

    ngx_conf_merge_uint_value(conf->access, prev->access, 0600);

    ngx_conf_merge_value(conf->create_full_put_path,
                         prev->create_full_put_path, 0);

    return NGX_CONF_OK;
}

/*      // 这是官方版本的处理方式，暂且保留
static ngx_int_t
ngx_http_dav_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_dav_handler;

    return NGX_OK;
}
*/

static char *
ngx_http_dav_deal_with(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_dav_handler;

    return NGX_OK;
}
