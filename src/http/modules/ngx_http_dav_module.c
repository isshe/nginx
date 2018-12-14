
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

//#define NGX_HTTP_DAV_OFF             2

#define NGX_HTTP_DAV_NO_DEPTH        -3
#define NGX_HTTP_DAV_INVALID_DEPTH   -2
#define NGX_HTTP_DAV_INFINITY_DEPTH  -1
#define NGX_HTTP_MULTI_STATUS        207
#define NGX_HTTP_DAV_ERROR_CODE_LEN  3
#define NGX_HTTP_DAV_ERROR_CODE_MIN  400
#define NGX_HTTP_DAV_ERROR_CODE_MAX  999
#define NGX_HTTP_DAV_MAX_INT_LEN     64

static ngx_path_init_t  ngx_http_dav_client_temp_path = {
        ngx_string(NGX_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};

typedef struct {
    ngx_uint_t  methods;                    // 允许的方法
    ngx_uint_t  access;
    ngx_uint_t  min_delete_depth;
    ngx_flag_t  create_full_put_path;
    ngx_str_t   subrequest_uri;             // 子请求的uri，再conf里设置
    size_t      upload_limit_rate;                 // 限速
    ngx_path_t  *dav_client_body_temp_path;
} ngx_http_dav_loc_conf_t;

typedef struct {
    ngx_str_t   path;
    size_t      len;
} ngx_http_dav_copy_ctx_t;

struct ngx_http_dav_ctx_s;

typedef ngx_int_t (*ngx_http_request_body_data_handler_pt)
        (ngx_http_request_t *, struct ngx_http_dav_ctx_s*, u_char *, size_t);

// 请求的上下文，每个请求一份
typedef struct ngx_http_dav_ctx_s{
    ngx_str_t sub_req_args;                 // 子请求的参数，如：method=propfind&user=isshe&dst=/files/&Depth=1&data=xxx
    ngx_int_t status;                       // 子请求返回的json数据里的状态
    ngx_str_t data;                         // 子请求返回的json数据里的具体数据
    ngx_str_t src;                          // 想要操作的源文件（相对路径）
    ngx_str_t dst;                          // 想要操作的目的文件（相对路径）
    size_t    upload_limit_rate;            // 限速
    ssize_t   upload_received;              // 已接收
    ngx_uint_t response_status;             // 响应给用户的状态，当前只和put请求相关
    ngx_http_request_body_data_handler_pt data_handler;             // 限速的时候处理数据
    ngx_chain_t *to_write;
    ngx_uint_t use_temp_file;               // 是否使用了临时文件
    ngx_file_t file;                        // 用于保存要操作的文件信息（当前用于PUT）
    ngx_file_t dst_file;                    // 目标文件
} ngx_http_dav_ctx_t;

static ngx_int_t ngx_http_dav_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_get_head_handler(ngx_http_request_t *r);

static void ngx_http_dav_put_handler(ngx_http_request_t *r);
static void ngx_http_dav_propfind_subreq_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_dav_delete_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_delete_path(ngx_http_request_t *r,
    ngx_str_t *path, ngx_uint_t dir);
static ngx_int_t ngx_http_dav_delete_dir(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_delete_file(ngx_tree_ctx_t *ctx, ngx_str_t *path);
static ngx_int_t ngx_http_dav_noop(ngx_tree_ctx_t *ctx, ngx_str_t *path);

static ngx_int_t ngx_http_dav_mkcol_handler(ngx_http_request_t *r,
    ngx_http_dav_loc_conf_t *dlcf);

static ngx_int_t ngx_http_dav_propfind_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_dav_options_handler(ngx_http_request_t *r);

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

/**
 * 子请求返回后的处理方法
 * @param r
 * @param data
 * @param rc
 * @return
 */
static ngx_int_t ngx_http_dav_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);


/**
 * 子请求结束后激活的父请求的回调方法
 * @param r
 */
static void ngx_http_dav_post_handler(ngx_http_request_t *r);


/**
 * 创建子请求
 * @param r
 * @param sub_uri
 * @param sub_args
 * @return 处理结果
 */
static ngx_int_t ngx_http_dav_subrequest_create(ngx_http_request_t *r,
                                                ngx_str_t *sub_uri,
                                                ngx_str_t *sub_args,
                                                ngx_http_post_subrequest_pt post_handler,
                                                void *data);

/**
 * 生成子请求的的参数字符串
 * @param r
 * @param method
 * @param src
 * @param dst
 * @return 生成的字符串
 */
static ngx_str_t subrequest_args_generate(ngx_http_request_t *r,
                                          ngx_str_t *method,
                                          ngx_str_t *src,
                                          ngx_str_t *dst);

/**
 * 数字转字符串
 * @param r
 * @param num
 * @return
 */
static ngx_str_t off_to_ngx_str(ngx_http_request_t *r, off_t num);

/**
 * 用char *生成 ngx_str_t
 * @param pool
 * @param str
 * @return 新分配的字符串
 */
static ngx_str_t ngx_str_generator(ngx_pool_t *pool, const char *str);


/**
 * 获取destination，排除host部分，注意这个函数只是返回一个指针，里面的内容不能改！
 * @param r
 * @param dest
 * @return
 */
static u_char *ngx_http_dav_destination_get(ngx_http_request_t *r, ngx_table_elt_t *dest);

/**
 * 获取destination，结果存在res_uri,只是指向原请求的destination（不是重新分配内存），
 * 所以返回的res_uri里面的内容，尽量不要修改
 * @param r
 * @param res_uri
 * @return
 */
static ngx_int_t destination_uri_string_get(ngx_http_request_t *r, ngx_str_t *res_uri);


/**
 * 代替官方的处理方式，只处理对应location的请求
 * @param cf
 * @param cmd
 * @param conf
 * @return
 */
static char *ngx_http_dav_deal_with(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


/**
 * char * 类型复制为 ngx_str_t类型
 * @param pool
 * @param src
 * @param len
 * @return 新的字符串（新分配内存）
 */
static ngx_str_t ngx_str_copy_from_str(ngx_pool_t *pool, const char *src, ngx_int_t len);

/**
 * 字符串拼接
 * @param pool
 * @param str1
 * @param str2
 * @param str3
 * @return 新的字符串（新分配内存）
 */
static ngx_str_t ngx_http_dav_string_splice(ngx_pool_t *pool, ngx_str_t *str1, ngx_str_t *str2, ngx_str_t *str3);

/**
 * 替换uri和destination
 * @param r
 * @param resp_ctx
 * @return ngx_int_t
 */
static ngx_int_t ngx_http_dav_replace_uri_dst(ngx_http_request_t *r, ngx_http_dav_ctx_t *resp_ctx);

/**
 * 更新请求上下文
 * @param r ：请求
 * @param status_json
 * @param data_json
 * @return 操作结果
 */
static ngx_int_t ngx_http_dav_update_context(ngx_http_request_t *r,
                                             ngx_http_dav_ctx_t *resp_ctx,
                                             const ngx_json* status_json,
                                             const ngx_json* data_json);

/**
 * 读子请求的响应，放到res里面
 * @param r
 * @param res
 * @return 操作结果
 */
static ngx_int_t ngx_http_dav_read_subrequest_response(ngx_http_request_t *r, ngx_str_t *res);

/**
 * 检查返回的响应里面的data字段，如果是相关的错误码，就返回HTTP对应的错误码
 * @param r
 * @return 具体错误码 或 NGX_HTTP_OK
 */
static ngx_int_t ngx_http_dav_check_error(ngx_http_request_t *r, const char *str, ngx_int_t len);


/**
 * 获取propfind的data，如果请求里面的data有'\n'，就转换为"%0A"
 * @param r
 * @param bufs
 * @return data_str
 */
static ngx_str_t ngx_http_dav_propfind_data_get(ngx_http_request_t *r, ngx_chain_t *bufs);


/**
 * 字符串转换为数字，只做最简单的转换
 * @param str：字符串
 * @param len：字符串长度
 * @param ok：转换结果：0失败，1成功
 * @return 转换好的数字
 */
static ngx_int_t ngx_http_dav_atoi(const char *str, ngx_int_t len, ngx_int_t *ok);

/**
 * 用来写文件，文件路径再uri中，映射得到绝对路径并保存到ctx中；打开的fd也保存到ctx中
 * @param r
 * @param ctx
 * @param begin
 * @param len
 * @return
 */
static ngx_int_t ngx_http_dav_write_dst_file(ngx_http_request_t *r,
    ngx_http_dav_ctx_t *ctx, u_char *begin, size_t len);

/**
 * 处理用户上传的文件后，用这个来发送响应请求
 * @param r
 * @param ctx
 */
static void ngx_http_dav_send_response_handler(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx);

/**
 * 读用户请求体
 * @param r
 * @return
 */
ngx_int_t ngx_http_dav_read_client_request_body(ngx_http_request_t *r);

/**
 * （上传文件时）读用户请求体的read_event_handler
 * @param r
 */
static void ngx_http_dav_read_client_request_body_handler(ngx_http_request_t *r);

/**
 * 实际处理用户请求体的函数，这个函数里面可以进行限速
 * @param r
 * @return
 */
static ngx_int_t ngx_http_dav_do_read_client_request_body(ngx_http_request_t *r);

/**
 * 对读到的数据进行一些操作，当前是直接调用ngx_http_dav_write_dst_file进行写文件
 * @param r
 * @param body
 * @return
 */
static ngx_int_t ngx_http_dav_process_request_body(ngx_http_request_t *r, ngx_chain_t *body);

/**
 * 做一些收尾工作：关闭文件描述符等
 * @param r
 * @param ctx
 */
static void ngx_http_dav_shutdown_ctx(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx);

/**
 * 把请求里面的路径映射成绝对路径并获取相关文件信息
 * @param r
 * @param ctx
 * @return
 */
static ngx_int_t ngx_http_dav_map_dst_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx);

/**
 * 新建并打开临时文件
 * @param r
 * @param ctx
 * @return
 */
static ngx_int_t ngx_http_dav_create_and_open_temp_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx);

/**
 * 移动文件（ctx->file => ctx->dst_file）
 * @param r
 * @param ctx
 * @return
 */
static ngx_int_t ngx_http_dav_move_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx);

static ngx_conf_bitmask_t  ngx_http_dav_methods_mask[] = {
    //{ ngx_string("off"), NGX_HTTP_DAV_OFF },
    { ngx_string("get"), NGX_HTTP_GET},
    { ngx_string("head"), NGX_HTTP_HEAD},
    { ngx_string("put"), NGX_HTTP_PUT },
    { ngx_string("delete"), NGX_HTTP_DELETE },
    { ngx_string("mkcol"), NGX_HTTP_MKCOL },
    { ngx_string("copy"), NGX_HTTP_COPY },
    { ngx_string("move"), NGX_HTTP_MOVE },
    { ngx_string("options"), NGX_HTTP_OPTIONS},
    { ngx_string("propfind"), NGX_HTTP_PROPFIND },
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

    { ngx_string("dav_subrequest_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, subrequest_uri),
      NULL },

    { ngx_string("dav_upload_limit_rate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, upload_limit_rate),
      NULL },

    { ngx_string("dav_client_body_temp_path"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_dav_loc_conf_t, dav_client_body_temp_path),
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

static ngx_str_t
ngx_str_copy_from_str(ngx_pool_t *pool, const char *src, ngx_int_t len)
{
    ngx_str_t dst = ngx_null_string;
    if (!pool || !src || len <= 0)
    {
        return dst;
    }

    dst.data = ngx_palloc(pool, len);
    if (!dst.data)
    {
        return dst;
    }

    dst.len = len;
    ngx_memcpy(dst.data, src, dst.len);

    return dst;
}

static ngx_int_t ngx_http_dav_get_head_handler(ngx_http_request_t *r)
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


    if (!(r->method & NGX_HTTP_GET) && !(r->method & NGX_HTTP_HEAD)) {
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

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http GET/HEAD filename: \"%s\"", path.data);

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

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

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
    if (r->method == NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);          // get/head没有请求体，有的话就丢了

    if (rc != NGX_OK) {
        return rc;
    }

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

    // 这里可以区分head和get请求，head请求的header_only = 1
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

static ngx_int_t
ngx_http_dav_replace_uri_dst(ngx_http_request_t *r, ngx_http_dav_ctx_t *resp_ctx)
{

    switch(r->method)
    {
        case NGX_HTTP_OPTIONS:
        case NGX_HTTP_PROPFIND:
            break;
        case NGX_HTTP_GET:
        case NGX_HTTP_HEAD:
        case NGX_HTTP_PUT:
        case NGX_HTTP_DELETE:
        case NGX_HTTP_MKCOL:
            if (resp_ctx->dst.len == 0 || resp_ctx->dst.data == NULL)
            {
                return NGX_ERROR;
            }
            r->uri = resp_ctx->dst;
            //r->unparsed_uri = r->uri;           //
            break;
        case NGX_HTTP_COPY:
        case NGX_HTTP_MOVE:
            if (resp_ctx->src.len == 0 || resp_ctx->src.data == NULL
                || resp_ctx->dst.len == 0 || resp_ctx->dst.data == NULL)
            {
                return NGX_ERROR;
            }

            r->uri = resp_ctx->src;
            //r->unparsed_uri = r->uri;           //
            // r->headers_in.destination一定不会为NULL
            r->headers_in.destination->value = resp_ctx->dst;
            break;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_update_context(ngx_http_request_t *r,
                            ngx_http_dav_ctx_t *resp_ctx,
                            const ngx_json* status_json,
                            const ngx_json* data_json)
{
    // 这里的status是公共的，类型也是确定的
    resp_ctx->status = status_json->int_value;

    const ngx_json *dst_json = ngx_json_get(data_json, "dst");
    if (dst_json->type == NX_JSON_STRING)
    {
        resp_ctx->dst = ngx_str_copy_from_str(r->pool, dst_json->text_value, ngx_strlen(dst_json->text_value));
        if (resp_ctx->dst.len <= 0 || !resp_ctx->dst.data)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: dst: memory alloc failed");
            return NGX_ERROR;
        }
    }

    const ngx_json *src_json = ngx_json_get(data_json, "src");
    if (src_json->type == NX_JSON_STRING)
    {
        resp_ctx->src = ngx_str_copy_from_str(r->pool, src_json->text_value, ngx_strlen(src_json->text_value));
        if (resp_ctx->src.len <= 0 || !resp_ctx->src.data)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: src: memory alloc failed");
            return NGX_ERROR;
        }
    }

    // 对uri和dst进行替换
    if (ngx_http_dav_replace_uri_dst(r, resp_ctx) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: replace uri and dst failed");
        return NGX_ERROR;
    }

    // 如果data是string，就复制到请求上下文
    if (data_json->type == NX_JSON_STRING)
    {
        resp_ctx->data = ngx_str_copy_from_str(r->pool, data_json->text_value, ngx_strlen(data_json->text_value));
        if (resp_ctx->data.len <= 0 || !resp_ctx->data.data) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get response context failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_read_subrequest_response(ngx_http_request_t *r, ngx_str_t *res)
{
    ngx_buf_t *precv_buf = NULL;

    if (r->upstream)        // 支持代理的方式
    {
        precv_buf = &r->upstream->buffer;
    }

    if (!precv_buf)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: subrequest has no response body");
        return NGX_ERROR;
    }

    // 读子请求返回的内容
    *res = ngx_str_copy_from_str(r->pool, (const char *)precv_buf->pos, precv_buf->last - precv_buf->pos);
    if (res->len <= 0 || !res->data)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: copy subrequest response failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

// 只做最简单的处理
static ngx_int_t
ngx_http_dav_atoi(const char *str, ngx_int_t len, ngx_int_t *ok)
{
    ngx_int_t res = 0;
    ngx_int_t i = 0;
    ngx_int_t cur_bit = 0;

    if (!str || len <= 0)
    {
        *ok = 0;
        return res;
    }

    *ok = 1;
    for (i = 0; i < len; i++)
    {
        if (str[i] < '0' || str[i] > '9')
        {
            *ok = 0;
            break;
        }

        cur_bit = str[i] - '0';
        res = res * 10 + cur_bit;
    }

    return res;
}

static ngx_int_t
ngx_http_dav_check_error(ngx_http_request_t *r, const char *str, ngx_int_t len)
{
    if (len <= 0 || !str)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // data里面的数据长度为3，并且转换为数字为[400-999]就视为后端返回的错误码
    if (len == NGX_HTTP_DAV_ERROR_CODE_LEN)  // 只检查3的情况
    {
        ngx_int_t ok;
        ngx_int_t error_code = ngx_http_dav_atoi((const char *)str, len, &ok);
        if (ok && error_code >= NGX_HTTP_DAV_ERROR_CODE_MIN
            && error_code <= NGX_HTTP_DAV_ERROR_CODE_MAX)
        {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "dav: get error code from back-end: %d", error_code);
            return error_code;
        }
    }

    return NGX_HTTP_OK;
}

static void
ngx_http_dav_shutdown_ctx(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx)
{
    // 这里做一些清理工作，当前什么也不需要做
}

static ngx_int_t
ngx_http_dav_process_request_body(ngx_http_request_t *r, ngx_chain_t *body)
{
    ngx_int_t rc;
    ngx_http_dav_ctx_t        *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);

    // Feed all the buffers into data handler
    while(body) {
        rc = ctx->data_handler(r, ctx, body->buf->pos, body->buf->last - body->buf->pos);

        if(rc != NGX_OK)
            return rc;

        body = body->next;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_do_read_client_request_body(ngx_http_request_t *r)
{
    ssize_t                     size, n, limit;
    ngx_connection_t            *c;
    ngx_http_request_body_t     *rb;
    ngx_http_dav_ctx_t          *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    ngx_int_t                   rc;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_msec_t                  delay;

    c = r->connection;
    rb = r->request_body;

    //ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0, "dav: http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {
                rc = ngx_http_dav_process_request_body(r, ctx->to_write);

                switch(rc) {
                    case NGX_OK:
                        break;
                    default:
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                ctx->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;

            if ((off_t)size > rb->rest) {
                size = (size_t)rb->rest;
            }

            if (ctx->upload_limit_rate) {
                limit = ctx->upload_limit_rate * (ngx_time() - r->start_sec + 1) - ctx->upload_received;

                if (limit < 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read,
                                  (ngx_msec_t) (- limit * 1000 / ctx->upload_limit_rate + 1));
                    return NGX_AGAIN;
                }

                if(limit > 0 && size > limit) {
                    size = limit;
                }
            }

            n = c->recv(c, rb->buf->last, size);

            //ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
            //               "dav: http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "dav: client closed prematurely connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;
            ctx->upload_received += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }

            if (ctx->upload_limit_rate) {
                // 速度 = 路程 / 时间
                // => 时间 = 路程 / 速度
                // 所以实现限速的方法就是：针对每次接收进行延时。
                delay = (ngx_msec_t) (n * 1000 / ctx->upload_limit_rate + 1);

                if (delay > 0) {
                    c->read->delayed = 1;
                    ngx_add_timer(c->read, delay);
                    return NGX_AGAIN;
                }
            }
        }

        //ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
        //               "http client request body rest %uz", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    rc = ngx_http_dav_process_request_body(r, ctx->to_write);

    ngx_http_dav_shutdown_ctx(r, ctx);

    if (ctx->use_temp_file) {
        if (ctx->response_status < NGX_HTTP_SPECIAL_RESPONSE) {
            // 把临时文件移动到目标目录
            ngx_http_dav_move_file(r, ctx);
        }
    }

    ngx_http_dav_send_response_handler(r, ctx);
    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_move_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx)
{
    ngx_ext_rename_file_t     ext;
    ngx_http_dav_loc_conf_t  *dlcf;

    // 如果文件存在，就先删除
    if (ctx->dst_file.valid_info) {
        // 是目录，就报错
        if (ngx_is_dir(&ctx->dst_file.info)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                        "dav: can not move dir");
            ctx->response_status = NGX_HTTP_CONFLICT;
            return NGX_ERROR;
        }

        // 删除原文件
        if (ngx_delete_file(ctx->dst_file.name.data) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                        "dav: delete file failed: %s", ctx->dst_file.name.data);
            ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return NGX_ERROR;
        }
    }

    // 进行移动
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);

    ext.access = 0;
    ext.path_access = dlcf->access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 0;
    ext.log = r->connection->log;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: rename %s => %s", ctx->file.name.data, ctx->dst_file.name.data);
    if (ngx_ext_rename_file(&ctx->file.name, &ctx->dst_file.name, &ext) != NGX_OK) {
        ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;;
    }

    return NGX_OK;
}

static void
ngx_http_dav_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_dav_ctx_t        *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    ngx_event_t               *rev = r->connection->read;
    ngx_http_core_loc_conf_t  *clcf;

    if (rev->timedout) {

        if(!rev->delayed) {
            r->connection->timedout = 1;
            ngx_http_dav_shutdown_ctx(r, ctx);
            ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
            return;
        }

        rev->timedout = 0;
        rev->delayed = 0;

        if (!rev->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(rev, clcf->client_body_timeout);

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                ngx_http_dav_shutdown_ctx(r, ctx);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }
    else{

        if (r->connection->read->delayed) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0,
                           "http read delayed");

            if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
                ngx_http_dav_shutdown_ctx(r, ctx);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

            return;
        }
    }

    rc = ngx_http_dav_do_read_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_dav_shutdown_ctx(r, ctx);
        ngx_http_finalize_request(r, rc);
    }
}

ngx_int_t
ngx_http_dav_read_client_request_body(ngx_http_request_t *r)
{
    ssize_t                    size, preread;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, **next;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_dav_ctx_t        *ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);

#if defined nginx_version && nginx_version >= 8011
    r->main->count++;
#endif
    if (r->request_body || r->discard_body) {
        return NGX_OK;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n < 0) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_OK;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */
    preread = r->header_in->last - r->header_in->pos;

    if (preread || r->headers_in.content_length_n == 0) {

        /* there is the pre-read part of the request body */

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dav: http client request body preread %uz", preread);

        ctx->upload_received = preread;

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;
        rb->buf = b;

        // 意味着全部东西都在preread中了
        if (preread >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            // 处理请求体，当前是写到文件
            if (ngx_http_dav_process_request_body(r, rb->bufs) != NGX_OK) {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_OK;
            }

            // 处理完了，发送响应
            ngx_http_dav_send_response_handler(r, ctx);
            return NGX_OK;
        }

        /*
         * to not consider the body as pipelined request in
         * ngx_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        // rb-rest: 剩下需要读的
        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (off_t) (b->end - b->last)) {

            /* the whole request body may be placed in r->header_in */

            ctx->to_write = rb->bufs;

            // 设置好读回调，然后进行读
            r->read_event_handler = ngx_http_dav_read_client_request_body_handler;
            ngx_http_dav_do_read_client_request_body(r);
            return NGX_OK;
        }

        next = &rb->bufs->next;

    } else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    if (rb->rest < (ssize_t) size) {
        size = rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;

        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        size = b->last - b->pos;
        ngx_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    ctx->to_write = rb->bufs;

    r->read_event_handler = ngx_http_dav_read_client_request_body_handler;

    ngx_http_dav_do_read_client_request_body(r);
    return NGX_OK;
}


// 子请求结束后的处理方法
static ngx_int_t
ngx_http_dav_subrequest_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest status = %d", rc);

    // 如果子请求没有信息返回(precv_buf == NULL), 或者子请求出错，就直接返回错误
    if ((rc != NGX_OK && rc != NGX_HTTP_OK))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: subrequest status error");
        return NGX_OK;
    }

    ngx_http_request_t *pr = r->parent;
    // 备份写事件后改为自定义的写事件
    ngx_http_event_handler_pt write_event_handler_bk = pr->write_event_handler;
    pr->headers_out.status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    pr->write_event_handler = ngx_http_dav_post_handler;

    ngx_str_t sub_reply_json = ngx_null_string;
    if (ngx_http_dav_read_subrequest_response(r, &sub_reply_json) != NGX_OK)
    {
        return NGX_OK;
    }
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest return: %V", &sub_reply_json);

    // 读完以后，就进行json解析
    const ngx_json* json=ngx_json_parse(r->pool, (char *)sub_reply_json.data, NULL);
    if (json->type == NX_JSON_NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: json parse failed.");
        return NGX_OK;
    }

    // status是一定有的，如果没有，就是出错了
    const ngx_json *status_json = ngx_json_get(json, "status");
    const ngx_json *data_json = ngx_json_get(json, "data");

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest response body status type = %d", status_json->type);

    if (status_json->type != NX_JSON_INTEGER
        || status_json->int_value != 0
        || data_json->type == NX_JSON_NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: json info incorrect.");
        return NGX_OK;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest response body status = %d", status_json->int_value);

    // 这里进行错误判断
    if (data_json->type == NX_JSON_STRING
        && (rc = ngx_http_dav_check_error(r, data_json->text_value,
                ngx_strlen(data_json->text_value))) != NGX_HTTP_OK)
    {
        pr->headers_out.status = rc;
        return NGX_OK;
    }

    // 保存到context中，供父请求使用
    // get perent request context
    ngx_http_dav_ctx_t *resp_ctx = ngx_http_get_module_ctx(pr, ngx_http_dav_module);
    if (!resp_ctx) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: get response context failed");
        return NGX_ERROR;
    }

    // 更新请求上下文
    if (ngx_http_dav_update_context(pr, resp_ctx, status_json, data_json) != NGX_OK)
    {
        return NGX_OK;
    }

    switch (pr->method) {

        case NGX_HTTP_PUT:
        {
            if (pr->uri.data[pr->uri.len - 1] == '/')
            {
                ngx_log_error(NGX_LOG_ERR, pr->connection->log, 0,
                              "cannot PUT to a collection");
                pr->headers_out.status = NGX_HTTP_CONFLICT;
                return NGX_OK;
            }

            pr->write_event_handler = write_event_handler_bk;             // 恢复回调
            resp_ctx->data_handler = ngx_http_dav_write_dst_file;
            resp_ctx->response_status = NGX_HTTP_OK;

            // NOT HTTP_V2
            rc = ngx_http_dav_read_client_request_body(pr);
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            return NGX_DONE;
        }
        case NGX_HTTP_OPTIONS:              // options 和 propfind请求都需要复制data
        case NGX_HTTP_PROPFIND:
        {
            // 这里PROPFIND是后台返回的，直接复制转发给用户
            if (data_json->type != NX_JSON_STRING) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "dav: the data returned by the subrequest is not a string");
                return NGX_OK;
            }

            break;
        }
    }

    pr->headers_out.status = NGX_HTTP_OK;
    // 这里不再设置写事件pr->write_event_handler = ngx_http_dav_post_handler
    return NGX_OK;
}

// 父请求的回调方法
static void
ngx_http_dav_post_handler(ngx_http_request_t *r)
{
    ngx_int_t rc = r->headers_out.status;
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "in parent request(method = %d): subrequest status = %d", r->method, rc);

    if (r->method != NGX_HTTP_PROPFIND)
    {
        r->main->count++;
    }

    if (rc != NGX_HTTP_OK && rc != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"subrequest return an error!");
        ngx_http_finalize_request(r, rc);
        return;
    }

    // get 放回父请求，因为子请求无法处理
    switch (r->method) {
        case NGX_HTTP_GET:
        {
            rc = ngx_http_dav_get_head_handler(r);
            break;
        }
        case NGX_HTTP_HEAD:
        {
            r->header_only = 1;
            rc = ngx_http_dav_get_head_handler(r);
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
        {
            rc = ngx_http_dav_copy_move_handler(r);
            break;
        }
        case NGX_HTTP_MOVE:
        {
            rc = ngx_http_dav_copy_move_handler(r);
            break;
        }
        case NGX_HTTP_OPTIONS:
        {
            rc = ngx_http_dav_options_handler(r);
            break;
        }
        case NGX_HTTP_PROPFIND:
        {
            rc = ngx_http_dav_propfind_handler(r);
            break;
        }
    }

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_dav_subrequest_create(ngx_http_request_t *r, ngx_str_t *sub_uri, ngx_str_t *sub_args,
                               ngx_http_post_subrequest_pt post_handler, void *data)
{
    if (!r || !sub_uri || sub_uri->len == 0 || sub_uri->data == NULL) {
        return NGX_DECLINED;
    }

    ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (!psr) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 设置子请求的回调
    psr->handler = ngx_http_dav_subrequest_post_handler;

    if (data)
    {
        psr->data = data;
    }

    ngx_http_request_t *sr;

    return ngx_http_subrequest(r, sub_uri, sub_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY);
}

static ngx_str_t off_to_ngx_str(ngx_http_request_t *r, off_t num)
{
    ngx_str_t res_str;

    res_str.data = ngx_palloc(r->pool, NGX_HTTP_DAV_MAX_INT_LEN);
    ngx_memset(res_str.data, 0, NGX_HTTP_DAV_MAX_INT_LEN);
    snprintf((char *)res_str.data, NGX_HTTP_DAV_MAX_INT_LEN, "%lld", num);

    res_str.len = ngx_strlen(res_str.data);
    return res_str;
}


static ngx_str_t
subrequest_args_generate(ngx_http_request_t *r,
                         ngx_str_t *method,
                         ngx_str_t *src,
                         ngx_str_t *dst)
{
    ngx_str_t method_prefix = ngx_string("method=");
    ngx_str_t user_prefix = ngx_string("user=");
    ngx_str_t src_prefix = ngx_string("src=");
    ngx_str_t dst_prefix = ngx_string("dst=");
    ngx_str_t content_size = ngx_string("size=");

    ngx_str_t *user = &r->headers_in.user;
    ngx_str_t *user_args = &r->args;
    ngx_table_elt_t *depth = r->headers_in.depth;
    ngx_table_elt_t *range = r->headers_in.range;
    ngx_str_t size_str = off_to_ngx_str(r, r->headers_in.content_length_n);

    ngx_str_t args;
    args.len = method_prefix.len + method->len
               + user_prefix.len + user->len
               + dst_prefix.len + dst->len
               + content_size.len + size_str.len
               + 3;                                     // 3-> &, &

    ngx_int_t cur_pos = args.len;                       // 固定部分的长度

    if (src && src->len > 0)
    {
        args.len += src_prefix.len + src->len + 1;      // 1 -> &
    }

    if (user_args && user_args->len > 0)
    {
        args.len += user_args->len + 1;
    }

    if (depth)
    {
        args.len += depth->key.len + depth->value.len + 2;  // '&xxx=yyy' = nr_x + nr_y + 2
    }

    if (range)
    {
        args.len += range->key.len + range->value.len + 2;  // '&xxx=yyy' = nr_x + nr_y + 2
    }

    args.data = ngx_palloc(r->pool, args.len);
    if (!args.data)
    {
        args.len = 0;
        return args;
    }

    ngx_snprintf(args.data, args.len, "%V%V&%V%V&%V%V&%V%V",
                 &method_prefix, method,
                 &user_prefix, user,
                 &content_size, &size_str,
                 &dst_prefix, dst);

    if (src && src->len > 0)
    {
        ngx_snprintf(args.data + cur_pos, args.len - cur_pos, "&%V%V", &src_prefix, src);
        cur_pos += src_prefix.len + src->len + 1;      // 1 -> &
    }

    if (user_args && user_args->len > 0) {
        ngx_snprintf(args.data + cur_pos, args.len - cur_pos, "&%V", user_args);
        cur_pos += user_args->len + 1;
    }

    if (depth)
    {
        ngx_snprintf(args.data + cur_pos, args.len - cur_pos, "&%V=%V", &depth->key, &depth->value);
        cur_pos += depth->key.len + depth->value.len + 2;  // '&xxx=yyy' = nr_x + nr_y + 2
    }

    if (range)
    {
        ngx_snprintf(args.data + cur_pos, args.len - cur_pos, "&%V=%V", &range->key, &range->value);
        cur_pos += range->key.len + range->value.len + 2;  // '&xxx=yyy' = nr_x + nr_y + 2
    }

    return args;
}

static ngx_str_t ngx_str_generator(ngx_pool_t *pool, const char *str)
{
    ngx_str_t res = ngx_null_string;

    ngx_int_t len = strlen(str);
    res.data = ngx_palloc(pool, len);
    if (!res.data)
    {
        return res;
    }

    res.len = len;
    ngx_memcpy(res.data, str, res.len);
    return res;
}

static ngx_str_t ngx_http_dav_string_splice(ngx_pool_t *pool, ngx_str_t *str1,
                                            ngx_str_t *str2, ngx_str_t *str3)
{
    ngx_str_t new_str = ngx_null_string;
    ngx_int_t len = str1->len + str2->len + str3->len;

    new_str.data = ngx_palloc(pool, len);
    if (!new_str.data)
    {
        return new_str;
    }

    new_str.len = len;
    ngx_snprintf(new_str.data, new_str.len, "%V%V%V", str1, str2, str3);
    return new_str;
}


static ngx_int_t
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

    rc = ngx_http_auth_basic_user(r);

    // 没有用户信息或者是解析错误，都返回错误
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "failed to get user");
        return NGX_HTTP_BAD_REQUEST;
    }

    // 提前校验
    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!(r->method & dlcf->methods)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: not allow method:methods = %d:%d", r->method, dlcf->methods);
        return NGX_DECLINED;
    }

    // 配置上下文, 这里是分配一个空的，在处理子请求的时候，再进行
    ngx_http_dav_ctx_t *resp_ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (!resp_ctx)
    {
        resp_ctx = ngx_palloc(r->pool, sizeof(ngx_http_dav_ctx_t));
        if (!resp_ctx)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "dav: get dav module ctx failed");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        // 清零 == 初始化各个成员
        ngx_memzero(resp_ctx, sizeof(ngx_http_dav_ctx_t));
        resp_ctx->upload_limit_rate = dlcf->upload_limit_rate;
        resp_ctx->file.fd = NGX_INVALID_FILE;
        resp_ctx->response_status = NGX_HTTP_OK;

        if (dlcf && dlcf->dav_client_body_temp_path
            && dlcf->dav_client_body_temp_path->conf_file
            && dlcf->dav_client_body_temp_path->line > 0) {
            resp_ctx->use_temp_file = 1;            // 当前PUT的使用可能使用临时文件，这里把标记打上
        }
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "dav: upload_limit_rate = %d.", dlcf->upload_limit_rate);

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "dav: dav_client_body_temp_path config line: %d",
                dlcf->dav_client_body_temp_path->line);
        if (dlcf->dav_client_body_temp_path->conf_file) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "dav: dav_client_body_temp_path config_file: %s",
                    dlcf->dav_client_body_temp_path->conf_file);
        }
        ngx_http_set_ctx(r, resp_ctx, ngx_http_dav_module);
    }

    if (dlcf->subrequest_uri.len <= 0 || dlcf->subrequest_uri.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: subrequest uri is not set");
        return NGX_DECLINED;
    }

    ngx_str_t sub_uri = dlcf->subrequest_uri; // ngx_string("/v1/admin/api/webdavd");
    ngx_str_t sub_src = ngx_null_string;
    ngx_str_t sub_dst = r->unparsed_uri;        // r->uri -> r->unparsed_uri
    ngx_str_t sub_method = ngx_null_string;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest uri = %V.", &sub_uri);

    // 以下准备子请求的URI
    switch (r->method) {
        case NGX_HTTP_GET:
        {
            sub_method = ngx_str_generator(r->pool, "get");
            break;
        }
        case NGX_HTTP_HEAD:
        {
            sub_method = ngx_str_generator(r->pool, "head");
            break;
        }
        case NGX_HTTP_OPTIONS:
        {
            sub_method = ngx_str_generator(r->pool, "options");
            break;
        }
        case NGX_HTTP_PUT:
        {
            // 不允许上传目录
            if (r->uri.data[r->uri.len - 1] == '/') {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "cannot PUT to a collection");
                return NGX_HTTP_CONFLICT;
            }
            sub_method = ngx_str_generator(r->pool, "put");
            break;
        }
        case NGX_HTTP_DELETE:
        {
            sub_method = ngx_str_generator(r->pool, "delete");
            break;
        }
        case NGX_HTTP_MKCOL:
        {
            // 只允许创建目录
            if (r->uri.data[r->uri.len - 1] != '/') {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "cannot MKCOL non-collection");
                return NGX_HTTP_CONFLICT;
            }
            sub_method = ngx_str_generator(r->pool, "mkcol");
            break;
        }
        case NGX_HTTP_COPY:
        {
            sub_method = ngx_str_generator(r->pool, "copy");
            if (destination_uri_string_get(r, &sub_dst) != NGX_OK) {
                return NGX_HTTP_BAD_REQUEST;
            }
            sub_src = r->unparsed_uri;              // r->uri -> r->unparsed_uri
            break;
        }
        case NGX_HTTP_MOVE:
        {
            sub_method = ngx_str_generator(r->pool, "move");
            if (destination_uri_string_get(r, &sub_dst) != NGX_OK) {
                return NGX_HTTP_BAD_REQUEST;
            }
            sub_src = r->unparsed_uri;              // r->uri -> r->unparsed_uri
            break;
        }
        case NGX_HTTP_PROPFIND:
        {
            sub_method = ngx_str_generator(r->pool, "propfind");
            // propfind 作特殊处理
            ngx_str_t sub_args = subrequest_args_generate(r, &sub_method, &sub_src, &sub_dst);
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "PROPFIND subrequest: uri = %V, args = %V, before replace.",
                          &sub_uri, &sub_args);

            // 保存到上下文中
            resp_ctx->sub_req_args = sub_args;
            //r->request_body_in_single_buf = 1;              // 放到1块buf里面，好读
            rc = ngx_http_read_client_request_body(r, ngx_http_dav_propfind_subreq_handler);
            if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }
            return NGX_DONE;
        }
    }

    ngx_str_t sub_args = subrequest_args_generate(r, &sub_method, &sub_src, &sub_dst);
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "COMMON subrequest: uri = %V, args = %V, before replace.",
                  &sub_uri, &sub_args);

    // 保存到上下文中
    resp_ctx->sub_req_args = sub_args;

    rc = ngx_http_dav_subrequest_create(r, &sub_uri, &sub_args,
            ngx_http_dav_subrequest_post_handler, NULL);
    if (rc != NGX_OK) {
        return NGX_DECLINED;
    }

    // 如果是OK，就证明子请求已经创建, 接下来一定要返回NGX_DONE
    return NGX_DONE;
}


static ngx_str_t ngx_http_dav_propfind_data_get(ngx_http_request_t *r, ngx_chain_t *bufs)
{
    ngx_chain_t *cl = NULL;
    ngx_buf_t *buf = NULL;
    int i = 0;
    int j = 0;
    ngx_str_t data_str = ngx_null_string;

    // 计算换行符个数
    ngx_int_t content_count = r->headers_in.content_length_n;
    if (content_count <= 0) {
        return data_str;
    }

    ngx_int_t lb_count = 0;

    for (cl = bufs; cl; cl = cl->next) {

        buf = cl->buf;

        for (i = 0; buf && buf->pos + i != buf->last; i++)
        {
            if (buf->pos[i] == '\n')
            {
                lb_count++;
            }
        }
    }

    // '\n' -> "%0A", 增加了2个字符
    data_str.len = content_count + (lb_count << 1);
    data_str.data = ngx_palloc(r->pool, data_str.len);
    if (!data_str.data)
    {
        data_str.len = 0;
        return data_str;
    }

    j = 0;
    for (cl = bufs; cl; cl = cl->next) {

        buf = cl->buf;

        for (i = 0; buf && buf->pos + i != buf->last; i++)
        {
            if (buf->pos[i] == '\n')
            {
                data_str.data[j++] = '%';
                data_str.data[j++] = '0';
                data_str.data[j++] = 'A';
            }
            else
            {
                data_str.data[j++] = buf->pos[i];
            }
        }
    }

    return data_str;
}

static void ngx_http_dav_propfind_subreq_handler(ngx_http_request_t *r)
{
    // 标准的propfind请求是有请求体(request body)的，因此这里做检测，如果没有，就直接返回错误
    ngx_uint_t status = NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (!r->request_body || !r->request_body->bufs || !r->request_body->bufs->buf)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: request body is empty");
        status = NGX_HTTP_BAD_REQUEST;
        ngx_http_finalize_request(r, status);
        return;
    }

    // 获取上下文
    ngx_http_dav_ctx_t *resp_ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    ngx_http_dav_loc_conf_t *dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    if (!resp_ctx || !dlcf)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "dav: get module context or location config failed");
        ngx_http_finalize_request(r, status);
        return;
    }

    // propfind请求的子请求需要有data部分，因此这里吧data作为参数给子请求
    //ngx_buf_t *b = r->request_body->bufs->buf;
    ngx_str_t data_prefix = ngx_string("&data=");
    ngx_str_t def_data = ngx_string("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                                    "<d:propfind xmlns:d=\"DAV:\"><d:allprop/></d:propfind>");
    ngx_str_t data_str = ngx_http_dav_propfind_data_get(r, r->request_body->bufs);
    if (data_str.len == 0 || !data_str.data)
    {
        data_str = def_data;
    }
    ngx_str_t new_args = ngx_http_dav_string_splice(r->pool,
            &resp_ctx->sub_req_args, &data_prefix, &data_str);
    if (new_args.len <= 0 || new_args.data == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: generate new args failed");
        ngx_http_finalize_request(r, status);
        return;
    }

    // 创建子请求
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "dav: subrequest new args = %V", &new_args);
    resp_ctx->sub_req_args = new_args;
    status = ngx_http_dav_subrequest_create(r, &dlcf->subrequest_uri,
            &resp_ctx->sub_req_args, ngx_http_dav_subrequest_post_handler, NULL);
    if (status != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: create subrequest failed");
        ngx_http_finalize_request(r, status);
        return;
    }
}

static ngx_int_t 
ngx_http_dav_map_dst_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx)
{
    size_t root = 0;
    ngx_str_t *filename = &ctx->dst_file.name;
    ngx_file_info_t *fileinfo = &ctx->dst_file.info;
    ctx->dst_file.valid_info = 0;

    if (ngx_http_map_uri_to_path(r, filename, &root, 0) == NULL) {
        ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    if (ngx_file_info(filename->data, fileinfo) == NGX_FILE_ERROR) {
        ctx->response_status = NGX_HTTP_CREATED;
    } else {
        ctx->response_status = NGX_HTTP_NO_CONTENT;
        ctx->dst_file.valid_info = 1;

        if (ngx_is_dir(fileinfo)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_EISDIR,
                        "dav: \"%s\" could not be created", filename->data);
            ctx->response_status = NGX_HTTP_CONFLICT;
            return NGX_ERROR;
        }
    }

    filename->len--;        // 长度忽略'\0'

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_create_and_open_temp_file(ngx_http_request_t *r, struct ngx_http_dav_ctx_s *ctx)
{
    ngx_path_t               *path;
    ngx_http_dav_loc_conf_t  *dlcf;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_dav_module);
    path = dlcf->dav_client_body_temp_path;
    if (path == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "dav: dav_client_body_temp_path is NULL!");
        ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    if (ngx_create_temp_file(&ctx->file, path, r->pool, 1, 1, NGX_FILE_DEFAULT_ACCESS) != NGX_OK)
    {

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dav: hashed path: error!");
        ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dav: hashed path: %s", ctx->file.name.data);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_write_dst_file(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx, u_char *begin, size_t len)
{
    ngx_fd_t  fd;
    ngx_file_info_t fi;
    ngx_uint_t status = NGX_HTTP_OK;
    ngx_int_t res = NGX_OK;

    // 可以等于0，因为上传空文件时，就是0
    if (!begin) {
        if (ctx->file.fd != NGX_INVALID_FILE && ngx_close_file(ctx->file.fd) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      ngx_close_file_n " \"%V\" failed", &ctx->file.name);
        }
        ctx->file.fd = NGX_INVALID_FILE;
        return NGX_OK;
    }

    // 打开文件
    if (ctx->file.fd == NGX_INVALID_FILE) {
        res = ngx_http_dav_map_dst_file(r, ctx);
        if (res != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: map dst file failed");
            ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return res;
        }

        // 使用临时文件
        if (ctx->use_temp_file) {
            res = ngx_http_dav_create_and_open_temp_file(r, ctx);
            if (res != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "dav: create temp file failed");
                ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return res;
            }
        } else {
            // 直接写到目标目录
            ctx->file.name.data = ctx->dst_file.name.data;
            ctx->file.name.len = ctx->dst_file.name.len;

            ctx->file.fd = ngx_open_file(ctx->file.name.data, NGX_FILE_RDWR,
                                        NGX_FILE_CREATE_OR_OPEN, NGX_FILE_DEFAULT_ACCESS);
            if (ctx->file.fd == NGX_INVALID_FILE) {
                (void) ngx_http_dav_error(r->connection->log, ngx_errno, 0,
                                            ngx_open_file_n, ctx->file.name.data);
                ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
                return NGX_ERROR;
            }
        }

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                        "dav: http put filename: \"%V\"", &ctx->file.name);
    }

    fd = ctx->file.fd;
    if (fd == NGX_INVALID_FILE) {
        (void) ngx_http_dav_error(r->connection->log, ngx_errno, 0,
                                    ngx_open_file_n, ctx->file.name.data);
        ctx->response_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        return NGX_ERROR;
    }

    // 写文件
    if (len > 0) {
        ssize_t wlen = ngx_write_fd(fd, begin, len);
        if (wlen == -1) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                          ngx_write_fd_n " to \"%V\" failed", &ctx->file.name);

        } else if ((size_t) wlen != len) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          ngx_write_fd_n " to \"%V\" was incomplete: %z of %uz",
                          &ctx->file.name, wlen, len);
        }
    }

    return NGX_OK;
}

static void
ngx_http_dav_send_response_handler(ngx_http_request_t *r, ngx_http_dav_ctx_t *ctx)
{
    ngx_uint_t                status = ctx->response_status;

    if (status == NGX_HTTP_CREATED) {
        if (ngx_http_dav_location(r, ctx->dst_file.name.data) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        r->headers_out.content_length_n = 0;
    }

    r->headers_out.status = status;
    r->header_only = 1;

    ngx_http_finalize_request(r, ngx_http_send_header(r));
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
ngx_http_dav_options_handler(ngx_http_request_t *r)
{
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dav: options");

    ngx_http_dav_ctx_t *resp_ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (!resp_ctx) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dav: get response context failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "DAV");
    ngx_str_set(&h->value, "1");
    h->hash = 1;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_str_set(&h->key, "Allow");
    h->value.len = resp_ctx->data.len;
    h->value.data = resp_ctx->data.data;
    //ngx_str_set(&h->value, "GET,HEAD,PUT,DELETE,MKCOL,COPY,MOVE,PROPFIND,OPTIONS");
    h->hash = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;

    ngx_http_send_header(r);

    return NGX_OK;
}

static ngx_int_t
ngx_http_dav_propfind_handler(ngx_http_request_t *r)
{
    // 获取请求上下文，子请求已经进行保存
    ngx_http_dav_ctx_t *resp_ctx = ngx_http_get_module_ctx(r, ngx_http_dav_module);
    if (!resp_ctx) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "dav: get response context failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    int bodylen = resp_ctx->data.len;
    ngx_buf_t *buf = ngx_create_temp_buf(r->pool, bodylen);
    if (!buf)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(buf->pos, resp_ctx->data.data, bodylen);
    buf->last = buf->pos + bodylen;
    buf->last_buf = 1;                      // 是最后一个buf
    ngx_chain_t out;
    out.buf = buf;
    out.next = NULL;
    r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;

    // 发送头部
    static ngx_str_t type = ngx_string("text/xml; charset=UTF-8");
    r->headers_out.content_type = type;
    r->headers_out.status = NGX_HTTP_MULTI_STATUS;
    r->headers_out.content_length_n = bodylen;
    ngx_str_set(&r->headers_out.status_line, "207 Multi-Status");

    ngx_int_t rc = ngx_http_send_header(r);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_output_filter(r, &out);
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

    // 不考虑源文件不存在的情况（uri为源，duri为目的）
    if (duri.len == r->uri.len && ngx_strncmp(duri.data, r->uri.data, duri.len) == 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "dav: src and dst uri are the same");
        return NGX_HTTP_NO_CONTENT;
    }

    if (ngx_http_parse_unsafe_uri(r, &duri, &args, &flags) != NGX_OK) {
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

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http copy/move from: \"%s\"", path.data);

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
     *     clcf->dav_client_body_temp_path = NULL;
     */

    conf->min_delete_depth = NGX_CONF_UNSET_UINT;
    conf->access = NGX_CONF_UNSET_UINT;
    conf->create_full_put_path = NGX_CONF_UNSET;
    conf->subrequest_uri.len = 0;
    conf->subrequest_uri.data = NULL;
    conf->upload_limit_rate = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_dav_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_dav_loc_conf_t  *prev = parent;
    ngx_http_dav_loc_conf_t  *conf = child;

    ngx_conf_merge_bitmask_value(conf->methods, prev->methods,
                         (NGX_CONF_BITMASK_SET));//|NGX_HTTP_DAV_OFF));

    ngx_conf_merge_uint_value(conf->min_delete_depth,
                         prev->min_delete_depth, 0);

    ngx_conf_merge_uint_value(conf->access, prev->access, 0600);

    ngx_conf_merge_value(conf->create_full_put_path,
                         prev->create_full_put_path, 0);

    ngx_conf_merge_str_value(conf->subrequest_uri, prev->subrequest_uri, "");

    ngx_conf_merge_size_value(conf->upload_limit_rate, prev->upload_limit_rate, 0);

    if (ngx_conf_merge_path_value(cf, &conf->dav_client_body_temp_path,
                              prev->dav_client_body_temp_path,
                              &ngx_http_dav_client_temp_path) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
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

    return NGX_CONF_OK;
}
