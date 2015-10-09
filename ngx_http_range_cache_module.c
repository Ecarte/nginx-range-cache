
/*
 * Copyright (C) Steven Hartland
 * Copyright (C) Multiplay (UK) Ltd
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    off_t        start;
    off_t        end;
} ngx_http_range_cache_range_t;

typedef struct {
    size_t      range_cache_size;
} ngx_http_range_cache_conf_t;

typedef struct {
    ngx_array_t                     ranges;
    ngx_http_range_cache_range_t    request_range;
    ngx_http_range_cache_range_t    range;
    ngx_uint_t                      range_idx;
    off_t                           content_length;
} ngx_http_range_cache_ctx_t;


static void *ngx_http_range_cache_create_conf(ngx_conf_t *cf);
static char *ngx_http_range_cache_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_range_cache_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_range_cache_range_variable(
    ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_range_cache_range_parse(ngx_http_request_t *r,
    ngx_http_range_cache_ctx_t *ctx);
static ngx_int_t ngx_http_range_cache_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_range_cache_content_range_parse(
    ngx_http_request_t *r, ngx_http_range_cache_ctx_t *ctx);


static ngx_command_t  ngx_http_range_cache_commands[] = {
    { ngx_string("range_cache_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_range_cache_conf_t, range_cache_size),
      NULL },

      ngx_null_command
};

static ngx_http_variable_t  ngx_http_range_cache_vars[] = {
    { ngx_string("range_cache_range"), NULL,
      ngx_http_range_cache_range_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_module_t  ngx_http_range_cache_module_ctx = {
    ngx_http_range_cache_add_variables,     /* preconfiguration */
    ngx_http_range_cache_init,              /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_range_cache_create_conf,       /* create location configuration */
    ngx_http_range_cache_merge_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_range_cache_module = {
    NGX_MODULE_V1,
    &ngx_http_range_cache_module_ctx,       /* module context */
    ngx_http_range_cache_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_range_cache_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_range_cache_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_range_cache_header_filter(ngx_http_request_t *r)
{
    off_t                           start, end;
    ngx_table_elt_t                 *content_range;
    ngx_http_range_cache_range_t    *range;
    ngx_http_range_cache_ctx_t      *ctx, *ctx_main;
    ngx_http_range_cache_conf_t     *conf;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter - start: %p", r);

    if (r->headers_out.status != NGX_HTTP_OK &&
            r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range cacheable: header filter - skip initial");
        return ngx_http_next_header_filter(r);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_range_cache_module);
    if (conf->range_cache_size == NGX_CONF_UNSET_SIZE) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range cacheable: header filter - skip no size");
        return ngx_http_next_header_filter(r);
    }

    ctx_main = ngx_http_get_module_ctx(r->main, ngx_http_range_cache_module);
    if (ctx_main == NULL) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http range cacheable: header filter - skip no main ctx");
        return ngx_http_next_header_filter(r);
    }

    if (r == r->main) {
        ctx = ctx_main;
    } else {
        ctx = ngx_http_get_module_ctx(r, ngx_http_range_cache_module);
        if (ctx_main == NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http range cacheable: header filter - skip no main ctx");
            return ngx_http_next_header_filter(r);
        }
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter run");
    if (ngx_http_range_cache_content_range_parse(r, ctx) != NGX_OK) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: header filter - skip invalid content range");
        return ngx_http_next_header_filter(r);
    }
    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http range cacheable: header filter content_length: %O, start: %O, end: %O",
                   ctx_main->content_length, ctx->range.start, ctx_main->range.end);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter content_range: %V, %d",
                   &r->headers_out.content_range->value,
                   r->headers_out.content_range->hash);


    if (r->headers_out.content_range == NULL) {
        content_range = ngx_list_push(&r->headers_out.headers);
        if (content_range == NULL) {
            return NGX_ERROR;
        }
        r->headers_out.content_range = content_range;
        content_range->hash = 1;
        ngx_str_set(&content_range->key, "Content-Range");
    } else {
        content_range = r->headers_out.content_range;
    }

    content_range->value.data = ngx_pnalloc(r->pool,
                                    sizeof("bytes -/") + 3 * NGX_OFF_T_LEN);
    if (content_range->value.data == NULL) {
        return NGX_ERROR;
    }

    if (r == r->main) {
        range = ctx->ranges.elts;
        start = range->start;
    } else {
      start = ctx->range.start;
    }

    // "Content-Range: bytes SSSS-EEEE/TTTT" header
    content_range->value.len = ngx_sprintf(content_range->value.data,
                                           "bytes %O-%O/%O%Z",
                                           start, ctx_main->range.end,
                                           ctx_main->content_length)
                               - content_range->value.data - 1;


    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter content_range: %V new",
                   &r->headers_out.content_range->value);

    start = ngx_max(ctx->range.start, ctx_main->range.start);
    end = ngx_min(ctx->range.end, ctx_main->range.end);

    r->headers_in.range->value.len = ngx_sprintf(r->headers_in.range->value.data,
            "bytes=%O-%O%Z", start, end) - r->headers_in.range->value.data - 1;

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter - r.start: %O, r.end: %O, main.start: %O, main.end: %O",
                   ctx->range.start, ctx->range.end, ctx_main->range.start, ctx_main->range.end);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: header filter - range: %V, content_range: %V, content_length: %O",
                   &r->headers_in.range->value,
                   &content_range->value,
                   r->headers_out.content_length_n);

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_range_cache_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_int_t                           rc;
    ngx_uint_t                          last;
    ngx_chain_t                         *cl;
    ngx_http_request_t                  *sr;
    ngx_http_range_cache_ctx_t      *ctx;
    ngx_http_range_cache_range_t    *ranges;

    if (in == NULL || r->header_only) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: body filter - skip initial");
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_range_cache_module);
    if (ctx == NULL || ctx->range_idx >= ctx->ranges.nelts) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: body filter - skip ctx");
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    rc = ngx_http_next_body_filter(r, in);

    if (rc == NGX_ERROR || !last) {
        return rc;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http range cacheable: body filter - start range %d => %d ",
                  ctx->range_idx, ctx->ranges.nelts);

    ranges = ctx->ranges.elts;
    for (; ctx->range_idx < ctx->ranges.nelts; ctx->range_idx++) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: subrequest: %d start", ctx->range_idx);

        if (ngx_http_subrequest(r, &r->uri, &r->args, &sr, NULL, NGX_HTTP_SUBREQUEST_WAITED)
            != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "http range cacheable: subrequest: %d failed",
                          ctx->range_idx);
            return NGX_ERROR;
        }

        sr->headers_in.range = ngx_pcalloc(r->pool, sizeof(ngx_table_elt_t));
        if (sr->headers_in.range == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(sr->headers_in.range, r->headers_in.range, sizeof(ngx_table_elt_t));

        sr->headers_in.range->value.data = ngx_pnalloc(r->pool,
            sizeof("bytes= -") + 2 * NGX_OFF_T_LEN);
        if (sr->headers_in.range->value.data == NULL) {
            return NGX_ERROR;
        }

        sr->headers_in.range->value.len = ngx_sprintf(
            sr->headers_in.range->value.data, "bytes=%O-%O%Z",
            ranges[ctx->range_idx].start,
            ranges[ctx->range_idx].end) - sr->headers_in.range->value.data - 1;

        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: subrequest: %d @ %p range: %V",
                      ctx->range_idx, sr, &sr->headers_in.range->value);
    }

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http range cacheable: subrequests done");

    return ngx_http_send_special(r, NGX_HTTP_LAST);
}

static ngx_int_t
ngx_http_range_cache_init(ngx_conf_t *cf)
{

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_range_cache_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_range_cache_body_filter;

    return NGX_OK;
}


static void *
ngx_http_range_cache_create_conf(ngx_conf_t *cf)
{
    ngx_http_range_cache_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_range_cache_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->range_cache_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_http_range_cache_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_range_cache_conf_t *prev = parent;
    ngx_http_range_cache_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->range_cache_size,
                              prev->range_cache_size, NGX_CONF_UNSET_SIZE);

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_range_cache_range_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    off_t                               start, end, size;
    ngx_int_t                           i, j, rc;
    ngx_http_range_cache_ctx_t      *ctx;
    ngx_http_range_cache_range_t    *rp;
    ngx_http_range_cache_conf_t	*conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_range_cache_module);

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http range cacheable: variable");
    if (conf->range_cache_size == NGX_CONF_UNSET_SIZE
        || r->headers_in.range == NULL
        || r->headers_in.range->value.len < 7
        || ngx_strncasecmp(r->headers_in.range->value.data,
                           (u_char *) "bytes=", 6) != 0) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: variable skip");
        v->not_found = 1;

        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_range_cache_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_range_cache_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
    
        if (r == r->main) {
            if (ngx_array_init(&ctx->ranges, r->pool, 1,
                sizeof(ngx_http_range_cache_range_t)) != NGX_OK)
            {
                return NGX_ERROR;
            }
        }
        ctx->range_idx = NGX_CONF_UNSET_UINT;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: calculate from r: %p range: %V",
                      r, &r->headers_in.range->value);
        rc = ngx_http_range_cache_range_parse(r, ctx);
        if (rc != NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "http range cacheable: skip rc: %d", rc);
            v->not_found = 1;
            return NGX_OK;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_range_cache_module);
    }

    rp = &ctx->range;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http range cacheable: variable range: idx: %d, type: %s, value: %V",
                   ctx->range_idx, r == r->main ? "main" : "subrequest",
                   &r->headers_in.range->value);

    v->data = ngx_pnalloc(r->pool,
              sizeof("bytes= -") + 2 * NGX_OFF_T_LEN);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "http range cacheable: variable start: %O, end: %O, size: %O, "
                  "range_cache_size: %O", rp->start, rp->end,
                   rp->end - rp->start + 1,
                   conf->range_cache_size);

    size = conf->range_cache_size * 2;

    i = rp->start / size;
    j = rp->end / size;
    start = i * size;
    end = start + size - 1;
    v->len = ngx_sprintf(v->data, "bytes=%O-%O%Z", start, end) - v->data - 1;

    if (r == r->main && ctx->range_idx == NGX_CONF_UNSET_UINT) {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: additional ranges - i: %d, j: %d",
                      i, j);

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: range hash: %d",
                       r->headers_in.range->hash);

        // TODO: figure out why this doesn't replicate the behaviour of:
        // proxy_set_header Range $range_cache_range;
        /*
        range = ngx_list_push(&r->headers_in.headers);
        if (range == NULL) {
            return NGX_ERROR;
        }
        r->headers_in.range = range;
        range->hash = 1;
        ngx_str_set(&range->key, "Range");

        range->value.data = ngx_pnalloc(r->pool,
                  sizeof("bytes= -") + 2 * NGX_OFF_T_LEN);
        if (range->value.data == NULL) {
            return NGX_ERROR;
        }
        range->value.len = ngx_sprintf(
            range->value.data, "bytes=%O-%O%Z", start, end)
            - range->value.data - 1;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: range new: %V, strlen: %d, len: %d, last: %d",
                      &range->value, ngx_strlen(range->value.data),
                      range->value.len, range->value.data[range->value.len]);
        */

        rp = ngx_array_push(&ctx->ranges);
        if (rp == NULL) {
            return NGX_ERROR;
        }
        rp->start = start;
        rp->end = end;

        ctx->range_idx = 1;
        for (i++; i <= j; i++) {
            rp = ngx_array_push(&ctx->ranges);
            if (rp == NULL) {
                return NGX_ERROR;
            }
            rp->start = i * size;
            rp->end = rp->start + size - 1;
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "http range cacheable: additional range: %d, start: %O, end: %O",
                          i, rp->start, rp->end);
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: calculated %d additional range(s)",
                      ctx->ranges.nelts - 1);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_range_cache_range_parse(ngx_http_request_t *r,
    ngx_http_range_cache_ctx_t *ctx)
{
    u_char    *p;
    off_t    start, end;

    p = r->headers_in.range->value.data + 6;
    start = 0;
    end = 0;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return NGX_DECLINED;
    }

    if (*p < '0' || *p > '9') {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: not statisfiable - %c start not a number",
                      *p);
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        start = start * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if (*p++ != '-') {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: not statisfiable - %c not seperator",
                      *(p-1));
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p == ' ') { p++; }

    if (*p == ',' || *p == '\0') {
        return NGX_DECLINED;
    }

    if (*p < '0' || *p > '9') {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: not statisfiable - %c end not a number",
                      *p);
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        end = end * 10 + *p++ - '0';
    }

    while (*p == ' ') { p++; }

    if ((*p != '\0' && *p != '\x0d') || start > end) {
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "http range cacheable: not statisfiable - 0x%02d not null or %O > %O",
                       *p, start, end);
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    ctx->range.start = start;
    ctx->range.end = end;

    return NGX_OK;
}

static ngx_int_t
ngx_http_range_cache_content_range_parse(ngx_http_request_t *r,
    ngx_http_range_cache_ctx_t *ctx)
{
    u_char     *p;
    off_t      len;

    if (r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT) {
       return NGX_OK;
    }

    if (r->headers_out.content_range == NULL
       || r->headers_out.content_range->value.len == 0) {
       return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (r->headers_out.content_range->value.len < 7
        || ngx_strncasecmp(r->headers_out.content_range->value.data,
                           (u_char *) "bytes ", 6) != 0) {
       return NGX_DECLINED;
    }

    len = 0;

    p = r->headers_out.content_range->value.data + 6;

    while (*p == ' ') { p++; }

    while (*p >= '0' && *p <= '9') { p++; }

    if (*p++ != '-') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') { p++; }

    if (*p++ != '/') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    if (*p < '0' || *p > '9') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    while (*p >= '0' && *p <= '9') {
        len = len * 10 + *p++ - '0';
    }

    if (*p != '\0') {
        return NGX_HTTP_RANGE_NOT_SATISFIABLE;
    }

    ctx->content_length = len;

    return NGX_OK;
}

