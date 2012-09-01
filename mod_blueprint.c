/* 
    mod_blueprint.c 
    (C) 2010-2012 Masatoshi Teruya.
*/
#include "httpd.h"
#include "http_log.h"
#include "http_protocol.h"
#include "apr_strings.h"
#include "http_request.h"
#include "http_core.h"
#include "http_connection.h"
//#include <execinfo.h>
#include <ctype.h>
#include "apr_version.h"
#include "apu_version.h"
#include "oniguruma.h"
#include "ClearSilver.h"


/* MARK: Definition */
#define PRODUCT_NAME "Blueprint"
#define PRODUCT_VERSION "2.6b"
#define PRODUCT_NAME_LEN 9

// logging
#define BP_STDERR(fmt,...)({\
	char time_str[APR_CTIME_LEN]; \
	ap_recent_ctime( time_str, apr_time_now() ); \
	fprintf( stderr, "[%s] %s:%d:%s: " fmt " \n", time_str, __FILE__, __LINE__, __func__, ##__VA_ARGS__ ); \
})

#define BP_RERROR(r,lv,fmt,...)({\
	ap_log_rerror( APLOG_MARK, lv, 0, r, fmt, ##__VA_ARGS__ ); \
})
#define BP_SERROR(s,lv,fmt,...)({\
	ap_log_error( APLOG_MARK, lv, 0, s, fmt, ##__VA_ARGS__ ); \
})
#define BP_PERROR(p,lv,fmt,...)({\
	ap_log_perror( APLOG_MARK, lv, 0, p, fmt, ##__VA_ARGS__ ); \
})

#define BP_APR_STRERROR(ec)({\
	char strbuf[MAX_STRING_LEN]; \
	apr_strerror( ec, strbuf, MAX_STRING_LEN ); \
})

#define BP_CS_STRERROR(str,ec)({\
	string_init(str); \
	nerr_error_string( ec, str ); \
})

#define BP_RCSERROR(r,lv,fmt,nerr)({\
	STRING str; \
	string_init(&str); \
	nerr_error_string( nerr, &str ); \
	ap_log_rerror( APLOG_MARK, lv, 0, r, fmt, (char*)str.buf ); \
	string_clear(&str); \
})
#define BP_SCSERROR(s,lv,fmt,err)({\
	STRING str; \
	string_init(&str); \
	nerr_error_string( nerr, &str ); \
	ap_log_error( APLOG_MARK, lv, 0, s, fmt, (char*)str.buf ); \
	string_clear(&str); \
})
#define BP_PCSERROR(p,lv,fmt,err)({\
	STRING str; \
	string_init(&str); \
	nerr_error_string( nerr, &str ); \
	ap_log_perror( APLOG_MARK, lv, 0, p, fmt, (char*)str.buf ); \
	string_clear(&str); \
})

// default tag
#define BP_DEFAULT_TAGNAME "cs"
// output filter
#define BP_OUTPUT_FILTER_NAME "Blueprint"

// Server Config
typedef struct {
    apr_pool_t *p;
    OnigRegex regexp;
    const char *tag;
} bpServer_cfg;

// Ouput Filter Context
typedef struct {
    apr_pool_t *p;
    bpServer_cfg *cfg;
    ap_filter_t *f;
    apr_table_t *headers_out;
    // from backend header: X-Blueprint-Sendfile
    const char *xfile;
    // buffer
    void *mem;
    size_t bytes;
    int eos;
} bpFilterOut_ctx;

// ClearSilver Rendering Context
typedef struct {
    bpFilterOut_ctx *ctx;
    HDF *hdf;
    void *render;
    size_t bytes;
    apr_bucket_brigade *bb;
} bpCS_t;


/* global module structure */
module AP_MODULE_DECLARE_DATA blueprint_module;
#define GET_MODULE_CONFIG( module_config ) ap_get_module_config( module_config , &blueprint_module );


/* MARK: Cleanup Working Pool */
static apr_status_t CleanupServerCfg( void *ctx )
{
    if( ctx )
    {
        bpServer_cfg *conf = (bpServer_cfg*)ctx;
        onig_free( conf->regexp );
        onig_end();
    }
    
    return APR_SUCCESS;
}

/* MARK: Utilities */
/*
static void stack_trace( apr_pool_t *p, unsigned int lv )
{
    void *buf[lv];
    int addrs = backtrace( buf, lv );
    char **symbols = (char**)backtrace_symbols( buf, addrs );
    
    if( !symbols ){
        BP_STDERR( "%s", strerror( errno ) );
    }
    else
    {
        for( lv = 0; lv < addrs; lv++ ){
            BP_STDERR( "%s", symbols[lv] );
        }
        free(symbols);
    }
}
*/
static apr_status_t ReadFile( apr_pool_t *p, const char *path, void **mem, apr_size_t *bytes )
{
	apr_status_t rc = APR_SUCCESS;
	apr_finfo_t finfo = {0};
	apr_file_t *file = NULL;
	
	// check filesize
	if( ( rc = apr_stat( &finfo, path, APR_FINFO_SIZE, p ) ) == APR_SUCCESS &&
		( rc = apr_file_open( &file, path, APR_READ, APR_OS_DEFAULT, p ) ) == APR_SUCCESS )
	{
		if( !( *mem = malloc( finfo.size + 1 ) ) ){
			rc = APR_ENOMEM;
		}
		else if( ( rc = apr_file_read_full( file, *mem, finfo.size, bytes ) ) == APR_SUCCESS ){
			// !!!: must set NULL at end of string
			((char*)*mem)[*bytes] = '\0';
		}
		else {
			free( *mem );
		}
		apr_file_close( file );
	}
	
	return rc;
}

static const char *Table2Str( apr_pool_t *p, apr_table_t *tbl )
{
    char *ret = "", *buf;
    
    errno = 0;
    if( asprintf( &buf, "" ) == -1 ){
        BP_PERROR( p, APLOG_ERR, "failed to asprintf(): %s", strerror( errno ) );
    }
    else
    {
        apr_array_header_t *arr = (apr_array_header_t*)apr_table_elts( tbl );
        apr_table_entry_t *entry = (apr_table_entry_t*)arr->elts;
        char *line = NULL;
        int i;
        
        for( i = 0; i < arr->nelts; i++ )
        {
            if( asprintf( &line, "%s%s: %s" CRLF, buf, entry[i].key, entry[i].val ) == -1 ){
                ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p, "failed to Table2Str(): %s", strerror( errno ) );
            }
            else
            {
                free( buf );
                buf = NULL;
                if( asprintf( &buf, "%s", line ) == -1 ){
                    ap_log_perror( APLOG_MARK, APLOG_ERR, 0, p, "failed to Table2Str(): %s", strerror( errno ) );
                    buf = NULL;
                    free( line );
                    break;
                }
                free( line );
            }
        }
        
        if( buf ){
            ret = apr_pstrdup( p, buf );
            free( buf );
        }
    }
    
    return ret;
}

static unsigned int strByteCount( unsigned char c )
{
	int byte = 1;
	
	if( c <= 0x7f ){
		return 1;
	}
	else if( c <= 0xdf ){
		return 2;
	}
	else if( c <= 0xef ){
		return 3;
	}
	else if( c <= 0xf7 ){
		return 4;
	}
	else if( c <= 0xfb ){
		return 5;
	}
	else if( c <= 0xfd ){
		return 6;
	}

	return byte;
}

static size_t strposUTF8( const char *str, size_t len )
{
	char *ptr;
	unsigned int width = 0;
	size_t count = 0;
	size_t pos = 0;
	
	for( ptr = (char*)str; *ptr != '\0' && count++ < len; ptr += width ){
		pos += ( width = strByteCount( *ptr ) );
	}
	
	return pos;
}

/* MARK: ClearSilver Hook */

static NEOERR *csHookFileload( void *ctx, HDF *hdf, const char *uri, char **contents )
{
    apr_status_t rv = APR_SUCCESS;
    bpCS_t *cst = (bpCS_t*)ctx;
    request_rec *r = cst->ctx->f->r;
    request_rec *rr = NULL;
    const char *filepath = NULL;
    
    if( r->proxyreq )
    {
        const char *rpath = ap_document_root(r);
        
        if( uri[0] == '/' )
        {
            if( ( rv = apr_filepath_merge( (char**)&filepath, rpath, uri+1, APR_FILEPATH_TRUENAME|APR_FILEPATH_SECUREROOT, cst->ctx->p ) ) ){
                asprintf( contents, PRODUCT_NAME "[include] failed to include %s: %s\n", uri, BP_APR_STRERROR( rv ) );
                BP_RERROR( r, APLOG_ERR, "%s", *contents );
            }
        }
        else
        {
            if( r->finfo.fname )
            {
                const char *path = apr_pstrdup( cst->ctx->p, r->finfo.fname );
                char *tail = strrchr( path, '/' );
                size_t plen,rlen;
                
                // remove filename
                if( tail ){
                    tail[1] = '\0';
                }
                // cmp head
                if( ( plen = strlen( path ) ) >= ( rlen = strlen( rpath ) ) &&
                    ( plen == 0 || memcmp( path, rpath, rlen ) == 0 ) ){
                    path +=  rlen + 1;
                }
                uri = apr_pstrcat( cst->ctx->p, path, uri, NULL );
            }
            
            if( ( rv = apr_filepath_merge( (char**)&filepath, rpath, uri, APR_FILEPATH_TRUENAME|APR_FILEPATH_SECUREROOT, cst->ctx->p ) ) ){
                asprintf( contents, PRODUCT_NAME "[include] failed to include %s: %s\n", uri, BP_APR_STRERROR( rv ) );
                BP_RERROR( r, APLOG_ERR, "%s", *contents );
            }
        }
    }
    else if( !( rr = ap_sub_req_lookup_uri( uri, r, NULL ) ) ){
        asprintf( contents, PRODUCT_NAME "[include] failed to include: %s", uri );
        BP_RERROR( r, APLOG_ERR, "%s", *contents );
    }
    else
    {
        if( rr->status != HTTP_OK ){
            asprintf( contents, PRODUCT_NAME "[include] failed to include %s: status %d\n", uri, rr->status );
            BP_RERROR( r, APLOG_ERR, "%s", *contents );
        }
        else if( rr->finfo.filetype != APR_REG && rr->finfo.filetype != APR_LNK ){
            asprintf( contents, PRODUCT_NAME "[include] failed to include %s: %s\n", uri, BP_APR_STRERROR( APR_ENOENT ) );
            BP_RERROR( r, APLOG_ERR, "%s", *contents );
        }
        else {
            filepath = apr_pstrdup( cst->ctx->p, rr->finfo.fname );
        }
        ap_destroy_sub_req(rr);
    }

    if( filepath )
    {
        char *ext = rindex( filepath, '.' );
        
        if( strcmp( ext, ".hdf" ) == 0 )
        {
            NEOERR *nerr = STATUS_OK;
            
            if( ( nerr = hdf_read_file( hdf, filepath ) ) ){
                BP_RCSERROR( r, APLOG_ERR, "failed to hdf_read_string(): %s", nerr );
                free( nerr );
                asprintf( contents, PRODUCT_NAME "[include] failed to include %s\n", uri );
            }
            else {
                asprintf( contents, "" );
            }
        }
        else
        {
            apr_size_t bytes = 0;
            
            if( ( rv = ReadFile( cst->ctx->p, filepath, (void**)contents, &bytes ) ) ){
                BP_RERROR( r, APLOG_ERR, "failed to ReadFile(): %s, %s", filepath, BP_APR_STRERROR( rv ) );
                asprintf( contents, PRODUCT_NAME "[include] failed to include %s\n", uri );
            }
        }
    }
    
    return STATUS_OK;
}

/* MARK: ClearSilver Custom Functions 
    CSPARSE->output_ctx = cs_render( parse, ctx, callback );
    CS_FUNCTION->name = registered function name
*/
/*
    replace str
    return newstr
    e.g. <?tag var:substr( "str", start_at, length, "attach_str" ) ?>
*/
static NEOERR *csFuncSubstr( CSPARSE *parse, CS_FUNCTION *csf, CSARG *args, CSARG *result )
{
    char *str = NULL;
    char *tail = NULL;
    long int beg = 0;
    long int len = 0;
    /*
        This is similar to python's PyArg_ParseTuple, :
        s - string (allocated), i - int, A - arg ptr (maybe later)
    */
    NEOERR *nerr = cs_arg_parse( parse, args, "siis", &str, &beg, &len, &tail );
    
    result->op_type = CS_TYPE_STRING;
    result->s = "";
    
    if( nerr ){
        return nerr_pass( nerr );
    }
    else if( len < 1 ){
        asprintf( &result->s, PRODUCT_NAME "[substr]: invalid length %ld", len );
        free( str );
        free( tail );
    }
    else if( str )
    {
        size_t olen = strlen( str );
        
        str += strposUTF8( str, beg );
        if( len ){
            str[strposUTF8( str, len )] = '\0';
        }
        
        if( strlen( str ) < olen ){
            asprintf( &result->s, "%s%s", str, tail );
            free( str );
        }
        else {
            result->s = (char*)str;
        }
        free( tail );
    }
    
    return STATUS_OK;
}

/*
    check macro_name is defined
    e.g. <?tag if:ifdef( "macro_name" ) ?>
*/
static NEOERR *csFuncIfdef( CSPARSE *parse, CS_FUNCTION *csf, CSARG *args, CSARG *result )
{
    const char *str;
    NEOERR *nerr = cs_arg_parse( parse, args, "s", &str );
    
    result->op_type = CS_TYPE_NUM;
    result->n = 0;
    if( nerr ){
        return nerr_pass( nerr );
    }
    else if( str )
    {
        CS_MACRO *macro = parse->macros;
        
        if( macro )
        {
            do {
                if( strcmp( macro->name, str ) == 0 ){
                    result->n = 1;
                    break;
                }
            } while( ( macro = macro->next ) );
        }
    }
    
    return STATUS_OK;
}

/* MARK: ClearSilver Redering Callback */
// need a content-length
static NEOERR *csRender( void *ctx, char *str )
{
    size_t len;
    
    if( str && ( len = strlen( str ) ) )
    {
        bpCS_t *cst = (bpCS_t*)ctx;
        size_t eos = cst->bytes + len;
        
        if( eos > cst->bytes && !( cst->render = realloc( cst->render, eos + 1 ) ) ){
            return nerr_raise_errno( NERR_IO, "failed to realloc(): %s", strerror( errno ) );
        }
        memcpy( cst->render + cst->bytes, str, len );
        cst->bytes = eos;
        ((char*)cst->render)[eos] = 0;
    }
    
    return STATUS_OK;
}
// chunked transfer-encoding
static NEOERR *csRenderChunk( void *ctx, char *str )
{
    size_t len;
    
    if( str && ( len = strlen( str ) ) )
    {
        bpCS_t *cst = (bpCS_t*)ctx;
        
        apr_bucket *b = apr_bucket_pool_create( str, len, cst->ctx->p, cst->bb->bucket_alloc );
        if( !b ){
            return nerr_raise_errno( NERR_IO, "%s", "failed to apr_bucket_pool_create()" );
        }
        APR_BRIGADE_INSERT_TAIL( cst->bb, b );
    }
    
    return STATUS_OK;
}

/* MARK: Output Filter */
static void append_header_buffer( bpFilterOut_ctx *ctx, apr_bucket_brigade *bb )
{
    request_rec *r = ctx->f->r;
    char *entity;
    apr_bucket *headerBkt = NULL;
    
    // set headers_out
    apr_table_set( ctx->headers_out, "Content-Type", r->content_type );
    apr_table_set( ctx->headers_out, "Content-Length", apr_psprintf( ctx->p, "%lld", r->clength ) );
    // apr_table_compress( ctx->headers_out, APR_OVERLAP_TABLES_SET );
    if( !( entity = apr_psprintf( ctx->p, "%s %s" CRLF "%s" CRLF, r->protocol, ap_get_status_line( r->status ), Table2Str( ctx->p, ctx->headers_out ) ) ) ){
        BP_RERROR( r, APLOG_ERR, "failed to append_header_buffer(): %s", strerror( errno ) );
        APR_BRIGADE_INSERT_TAIL( bb, ap_bucket_error_create( HTTP_INTERNAL_SERVER_ERROR, strerror( errno ), r->pool, ctx->f->c->bucket_alloc ) );
    }
    else {
        headerBkt = apr_bucket_pool_create( entity, strlen( entity ), r->pool, ctx->f->c->bucket_alloc );
        APR_BRIGADE_INSERT_TAIL( bb, headerBkt );
    }
}

static int csPreflight( bpCS_t *cst )
{
    int rc = 0;
    char *embHDF = calloc( 0, sizeof( char ) );
    
    if( !embHDF ){
        rc = -1;
        BP_RERROR( cst->ctx->f->r, APLOG_ERR, "failed to calloc(): %s", strerror( errno ) );
    }
    else
    {
        bpFilterOut_ctx *ctx = cst->ctx;
        bpServer_cfg *cfg = ctx->cfg;
        request_rec *r = ctx->f->r;
        int status = ONIG_NORMAL;
        OnigRegion *region;
        OnigErrorInfo einfo;
        unsigned char *start, *end;
        size_t hdflen = 0;
        
        // create match region
        region = onig_region_new();
        start = (unsigned char*)ctx->mem;
        end = (unsigned char*)( ctx->mem + ctx->bytes );
        while( ( status = onig_search( cfg->regexp, (const unsigned char*)ctx->mem, end, start, end, region, ONIG_OPTION_NONE ) ) > ONIG_MISMATCH )
        {
            char *tail = ctx->mem + region->end[0];
            size_t ntail = strlen( tail );
            
            if( region->num_regs > 1 )
            {
                size_t elen = region->end[1] - region->beg[1];
                
                // extract hdf
                if( !( embHDF = realloc( embHDF, hdflen + elen + 2 ) ) ){
                    BP_RERROR( r, APLOG_ERR, "failed to realloc(): %s", strerror( errno ) );
                    rc = errno;
                    break;
                }
                memcpy( embHDF + hdflen, ctx->mem + region->beg[1], elen );
                hdflen += elen + 1;
                embHDF[hdflen-1] = '\n';
                embHDF[hdflen] = '\0';
            }
            
            // shift tail
            memmove( ctx->mem + region->beg[0], tail, ntail );
            // set new content length of document
            ctx->bytes = ctx->bytes - ( region->end[0] - region->beg[0] );
            ((char*)ctx->mem)[ctx->bytes] = '\0';
            // move to match line
            start = (unsigned char*)ctx->mem + region->beg[0];
            end = (unsigned char*)ctx->mem + ctx->bytes;
        }
        onig_region_free( region, 1 );
        // check regular expression error
        if( status < ONIG_MISMATCH ){
            unsigned char strbuf[ONIG_MAX_ERROR_MESSAGE_LEN];
            rc = status;
            onig_error_code_to_str( strbuf, status, &einfo );
            BP_RERROR( r, APLOG_ERR, "failed to onig_search(): %s", (char*)strbuf );
        }
        else if( rc == 0 )
        {
            NEOERR *nerr = NULL;
            // add hdf string
            if( hdflen && ( nerr = hdf_read_string( cst->hdf, (const char*)embHDF ) ) != STATUS_OK ){
                BP_RCSERROR( r, APLOG_ERR, "failed to hdf_read_string(): %s", nerr );
                free( nerr );
                rc = -1;
            }
        }
        free( embHDF );
    }
    
    return rc;
}

static CSPARSE *csCreateParser( bpCS_t *cst )
{
    CSPARSE *cs = NULL;
    NEOERR *nerr = NULL;
    
    csPreflight( cst );
    
    // set tag start and blueprint info
    if( ( nerr = hdf_set_value( cst->hdf, "Config.TagStart", cst->ctx->cfg->tag ) ) || 
        ( nerr = hdf_set_value( cst->hdf, PRODUCT_NAME ".version", PRODUCT_VERSION ) ) ){
        BP_RCSERROR( cst->ctx->f->r, APLOG_ERR, "failed to hdf_set_value(): %s", nerr );
        free( nerr );
        return NULL;
    }
    else
    {
        request_rec *r = cst->ctx->f->r;
        
        // output subprocess_env
        if( r->subprocess_env )
        {
            apr_array_header_t *arr = (apr_array_header_t*)apr_table_elts( r->subprocess_env );
            apr_table_entry_t *entry = (apr_table_entry_t*)arr->elts;
            char *key = NULL;
            int i;
            
            for( i = 0; i < arr->nelts; i++ )
            {
                // if key has "." separater
                if( index( entry[i].key, '.' ) )
                {
                    if( ( nerr = hdf_set_value( cst->hdf, entry[i].key, entry[i].val ) ) ){
                        BP_RCSERROR( r, APLOG_ERR, "failed to hdf_set_value(): %s", nerr );
                        free( nerr );
                    }
                }
                // add prefix ENV.
                else if( asprintf( &key, "ENV.%s", entry[i].key ) == -1 ){
                    BP_RERROR( r, APLOG_ERR, "failed to asprintf(): %s", strerror( errno ) );
                }
                else
                {
                    if( ( nerr = hdf_set_value( cst->hdf, key, entry[i].val ) ) ){
                        BP_RCSERROR( r, APLOG_ERR, "failed to hdf_set_value(): %s", nerr );
                        free( nerr );
                    }
                    free( key );
                }
            }
        }
    }
    
    // initialize cs
    if( ( nerr = cs_init( &cs, cst->hdf ) ) != STATUS_OK ){
        BP_RCSERROR( cst->ctx->f->r, APLOG_ERR, "failed to cs_init() %s", nerr );
        free( nerr );
    }
    // registar built-in func
    else if( ( nerr = cs_register_function( cs, "ifdef", 1, csFuncIfdef ) ) != STATUS_OK ||
             ( nerr = cs_register_function( cs, "substr", 4, csFuncSubstr ) ) != STATUS_OK ||
             ( nerr = cs_register_strfunc( cs, "url_escape", cgi_url_escape ) ) != STATUS_OK ||
             ( nerr = cs_register_strfunc( cs, "html_escape", cgi_html_escape_strfunc ) ) != STATUS_OK ||
             ( nerr = cs_register_strfunc( cs, "text_html", cgi_text_html_strfunc ) ) != STATUS_OK ||
             ( nerr = cs_register_strfunc( cs, "js_escape", cgi_js_escape ) ) != STATUS_OK ||
             ( nerr = cs_register_strfunc( cs, "html_strip", cgi_html_strip_strfunc ) ) != STATUS_OK ){
        BP_RCSERROR( cst->ctx->f->r, APLOG_ERR, "failed to register_function() %s", nerr );
        cs_destroy( &cs );
        cs = NULL;
        free( nerr );
    }
    // hook cs file load
    else{
        cs_register_fileload( cs, (void*)cst, csHookFileload );
    }
    
    return cs;
}

static const char *csCreate( bpCS_t **cst, bpFilterOut_ctx *ctx )
{
    const char *errstr = NULL;
    NEOERR *nerr = NULL;
    HDF *hdf = NULL;
    bpCS_t *ncst = NULL;
    
    // initialize hdf data set
    if( ( nerr = hdf_init( &hdf ) ) != STATUS_OK ){
        STRING str;
        string_init(&str);
        nerr_error_string( nerr, &str );
        errstr = apr_psprintf( ctx->p, "failed to hdf_init() %s", str.buf );
        string_clear(&str);
        free( nerr );
    }
    // create cst
    else if( !( ncst = apr_pcalloc( ctx->p, sizeof( bpCS_t ) ) ) ){
        errstr = apr_psprintf( ctx->p, "failed to apr_pcalloc() %s", BP_APR_STRERROR( APR_ENOMEM ) );
        hdf_destroy( &hdf );
    }
    else
    {
        ncst->ctx = ctx;
        ncst->hdf = hdf;
        if( !ctx->f->r->chunked ){
            ncst->render = malloc(0);
            ncst->bytes = 0;
        }
        *cst = ncst;
    }
    
    return errstr;
}


static void output( bpFilterOut_ctx *ctx, apr_bucket_brigade *pass )
{
    bpCS_t *cst = NULL;
    request_rec *r = ctx->f->r;
    apr_bucket_alloc_t *ba = ctx->f->c->bucket_alloc;
    apr_bucket *pageBkt = NULL;
    const char *errstr = NULL;
    
    if( ( errstr = csCreate( &cst, ctx ) ) ){
        BP_RERROR( r, APLOG_ERR, "failed to csCreate(): %s", errstr );
        r->status = HTTP_INTERNAL_SERVER_ERROR;
    }
    else
    {
        NEOERR *nerr = NULL;
        
        // add buf into hdf string if X-Blueprint-Sendfile
        if( ctx->xfile )
        {
            apr_status_t rc = APR_SUCCESS;
            
            r->finfo.fname = ctx->xfile;
            // append backend page to hdf
            if( ctx->bytes )
            {
                nerr = hdf_read_string( cst->hdf, (const char*)ctx->mem );
                // maybe syntax error
                if( nerr != STATUS_OK ){
                    errstr = "failed to hdf_read_string()";
                    BP_RCSERROR( ctx->f->r, APLOG_ERR, "failed to hdf_read_string(): %s", nerr );
                    free( nerr );
                }
            }
            free( ctx->mem );
            ctx->mem = NULL;
            ctx->bytes = 0;
            if( ( rc = ReadFile( ctx->p, ctx->xfile, &ctx->mem, &ctx->bytes ) ) )
            {
                errstr = "failed to ReadFile()";
                BP_RERROR( ctx->f->r, APLOG_ERR, "failed to ReadFile(): %s", BP_APR_STRERROR( rc ) );
                if( APR_STATUS_IS_ENOENT( rc ) ){
                    r->status = HTTP_NOT_FOUND;
                }
                else {
                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                }
            }
        }
        
        if( !pageBkt )
        {
            if( ctx->bytes < 1 ){
                r->status = HTTP_NO_CONTENT;
            }
            else
            {
                CSPARSE *cs = NULL;
                char *buf = NULL;
                
                if( ctx->bytes && !( cs = csCreateParser( cst ) ) ){
                    errstr = "failed to csCreate()";
                    BP_RERROR( r, APLOG_ERR, "%s", errstr );
                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                }
                else
                {
                    if( !( buf = malloc( ctx->bytes + 1 ) ) ){
                        errstr = "failed to malloc()";
                        BP_RERROR( r, APLOG_ERR, "failed to malloc(): %s", strerror( errno ) );
                        r->status = HTTP_INTERNAL_SERVER_ERROR;
                    }
                    else
                    {
                        size_t bytes = ctx->bytes;
                        
                        memcpy( (char*)buf, ctx->mem, bytes );
                        buf[bytes] = '\0';
                        cst->bb = pass;
                        
                        // parse
                        if( ( nerr = cs_parse_string( cs, buf, bytes ) ) != STATUS_OK ){
                            errstr = "failed to cs_parse_string()";
                            BP_RCSERROR( r, APLOG_ERR, "failed to cs_parse_string(): %s", nerr );
                            r->status = HTTP_INTERNAL_SERVER_ERROR;
                            free( nerr );
                        }
                        // render
                        else
                        {
                            if( r->chunked )
                            {
                                if( ( nerr = cs_render( cs, (void*)cst, csRenderChunk ) ) != STATUS_OK ){
                                    errstr = "failed to cs_render()";
                                    BP_RCSERROR( r, APLOG_ERR, "failed to cs_render(): %s", nerr );
                                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                                    free( nerr );
                                }
                            }
                            // set content length if not chunked transfer-coding
                            else
                            {
                                if( ( nerr = cs_render( cs, (void*)cst, csRender ) ) != STATUS_OK ){
                                    errstr = "failed to cs_render()";
                                    BP_RCSERROR( r, APLOG_ERR, "failed to cs_render(): %s", nerr );
                                    r->status = HTTP_INTERNAL_SERVER_ERROR;
                                    free( nerr );
                                }
                                // set content length if not chunked transfer-coding
                                else {
                                    pageBkt = apr_bucket_pool_create( apr_pmemdup( ctx->p, cst->render, cst->bytes ), cst->bytes, r->pool, ba );
                                    r->clength = cst->bytes;
                                }
                            }
                        }
                    }
                    cs_destroy( &cs );
                    free( cst->render );
                }
            }
        }
        hdf_destroy( &cst->hdf );
    }
    
    // if not chunked transfer-coding
    if( !r->chunked )
    {
        if( errstr ){
            r->assbackwards = 0;
            pageBkt = ap_bucket_error_create( r->status, "", r->pool, ba );
        }
        else {
            // add custom headers
            append_header_buffer( ctx, pass );
        }
        // add contents
        APR_BRIGADE_INSERT_TAIL( pass, pageBkt );
    }
    if( ctx->bytes ){
        free( ctx->mem );
    }
    
    // add eos(END OF STREAM) or eoc(END OF CONNECTION)
    APR_BRIGADE_INSERT_TAIL( pass, apr_bucket_eos_create( ba ) );
}



static apr_status_t bp_output_filter( ap_filter_t *f, apr_bucket_brigade *bb )
{
    bpServer_cfg *cfg = GET_MODULE_CONFIG( f->r->server->module_config );
    apr_status_t rc = APR_SUCCESS;
    bpFilterOut_ctx *ctx = NULL;
    apr_bucket_brigade *pass = NULL;
    apr_bucket *b,*next_b;
    
    if( !cfg ){
        ap_remove_output_filter( f );
        return ap_pass_brigade( f->next, bb );
    }
    // empty data
    else if( APR_BRIGADE_EMPTY( bb ) ){
        ap_remove_output_filter( f );
        return ap_pass_brigade( f->next, bb );
    }
    // context is null
    else if( !( ctx = f->ctx ) )
    {
        apr_pool_t *p = NULL;
        
        if( ( rc = apr_pool_create( &p, f->r->pool ) ) ){
            BP_RERROR( f->r, APLOG_ERR, "failed to apr_pool_create: %s", BP_APR_STRERROR( rc ) );
            ap_remove_output_filter( f );
            return ap_pass_brigade( f->next, bb );
        }
        else
        {
            // check x-blueprint-sendfile
            char *xfile = NULL;
            
            // check x-blueprint-sendfile
            if( ( xfile = (char*)apr_table_get( f->r->headers_out, "X-Blueprint-Sendfile" ) ) )
            {
                apr_status_t rv = APR_SUCCESS;
                char *path = xfile;
                const char *rpath = ap_document_root( f->r );
                char *merge = NULL;
                size_t plen,rlen;
                
                // xfile has root path
                 // cmp head
                if( ( plen = strlen( path ) ) >= ( rlen = strlen( rpath ) ) &&
                    ( plen == 0 || memcmp( path, rpath, rlen ) == 0 ) ){
                    path +=  rlen + 1;
                }
                // append rootpath
                if( ( rv = apr_filepath_merge( (char**)&merge, rpath, path, APR_FILEPATH_TRUENAME|APR_FILEPATH_SECUREROOT, p ) ) ){
                    char *errstr = BP_APR_STRERROR( rv );
                    BP_RERROR( f->r, APLOG_ERR, "failed to X-Blueprint-Sendfile %s: %s\n", xfile, errstr );
                    f->r->status = HTTP_INTERNAL_SERVER_ERROR;
                    APR_BRIGADE_INSERT_TAIL( bb, ap_bucket_error_create( f->r->status, errstr, f->r->pool, f->c->bucket_alloc ) );
                    APR_BRIGADE_INSERT_TAIL( bb, apr_bucket_eos_create( f->r->connection->bucket_alloc ) );
                    ap_remove_output_filter( f );
                    apr_pool_destroy( p );
                    return ap_pass_brigade( f->next, bb );
                }
                xfile = merge;
                apr_table_unset( f->r->headers_out, "X-Blueprint-Sendfile" );
            }
            
            // create new context
            if( !( ctx = (bpFilterOut_ctx*)apr_pcalloc( p, sizeof( bpFilterOut_ctx ) ) ) ){
                BP_RERROR( f->r, APLOG_ERR, "failed to create blueprint context: %s", BP_APR_STRERROR( APR_ENOMEM ) );
                APR_BRIGADE_INSERT_TAIL( bb, ap_bucket_error_create( HTTP_INTERNAL_SERVER_ERROR, BP_APR_STRERROR( APR_ENOMEM ), f->r->pool, f->c->bucket_alloc ) );
                ap_remove_output_filter( f );
                apr_pool_destroy( p );
                return ap_pass_brigade( f->next, bb );
            }
            ctx->p = p;
            ctx->cfg = cfg;
            ctx->f = f;
            ctx->eos = 0;
            ctx->bytes = 0;
            ctx->mem = NULL;
            ctx->xfile = xfile;
            ctx->headers_out = apr_table_clone( p, f->r->headers_out );
            apr_table_overlap( ctx->headers_out, f->r->err_headers_out, APR_OVERLAP_TABLES_SET );
            f->ctx = ctx;
            
            apr_table_set( ctx->headers_out, "X-Blueprint", PRODUCT_VERSION );
            // MARK: if not chunked transfer-coding set assbackwards 1 that means do not output headers from apache
            if( !f->r->chunked ){
                f->r->assbackwards = 1;
            }
        }
    }
    
    // create result brigate
    pass = apr_brigade_create( ctx->p, f->c->bucket_alloc );
    // loop over the current bucket brigade
    b = APR_BRIGADE_FIRST( bb );
    while( b != APR_BRIGADE_SENTINEL( bb ) )
    {
        next_b = APR_BUCKET_NEXT( b );
        APR_BUCKET_REMOVE( b );
        // if is meta-data
        if( APR_BUCKET_IS_METADATA( b ) )
        {
            // END OF STREAM
            if( APR_BUCKET_IS_EOS( b ) ){
                ctx->eos = 1;
                // APR_BRIGADE_INSERT_TAIL( pass, b );
                break;
            }
            // END OF CONNECTION
            else if( AP_BUCKET_IS_EOC( b ) ){
                ctx->eos = 1;
                // APR_BRIGADE_INSERT_TAIL( pass, b );
                break;
            }
            else if( APR_BUCKET_IS_FLUSH( b ) ){
                BP_RERROR( f->r, APLOG_ERR, "APR_BUCKET_IS_FLUSH" );
                //APR_BRIGADE_INSERT_TAIL( ctx->out, b );
                //break;
            }
            /*
            const char *metadata = NULL;
            size_t metalen = 0;
            // read meta bucket data
            if( rc = apr_bucket_read( b, &metadata, &metalen, APR_BLOCK_READ ) ){
                errstr = apr_strerror( rc, strbuf, MAX_STRING_LEN );
                break;
            }
            */
            APR_BRIGADE_INSERT_TAIL( pass, b );
        }
        else
        {
            const char *page = NULL;
            size_t len;
            
            // read the current bucket data
            if( ( rc = apr_bucket_read( b, &page, &len, APR_BLOCK_READ ) ) ){
                APR_BRIGADE_INSERT_TAIL( pass, ap_bucket_error_create( HTTP_INTERNAL_SERVER_ERROR, BP_APR_STRERROR( rc ), ctx->p, f->c->bucket_alloc ) );
                break;
            }
            else if( !( ctx->mem = realloc( ctx->mem, ctx->bytes + len + 1 ) ) ){
                APR_BRIGADE_INSERT_TAIL( pass, ap_bucket_error_create( HTTP_INTERNAL_SERVER_ERROR, strerror( errno ), ctx->p, f->c->bucket_alloc ) );
                break;
            }
            // copy
            memcpy( ctx->mem + ctx->bytes, page, len );
            ctx->bytes += len;
            ((char*)ctx->mem)[ctx->bytes] = '\0';
        }
        
        b = next_b;
    }
    
    // apr_brigade_cleanup( bb );
    // end of stream
    if( ctx->eos )
    {
        // render
        if( ctx->bytes || ctx->xfile ){
            output( ctx, pass );
        }
        /*
        // read the current bucket data
        rc = apr_brigade_pflatten( ctx->bb, (char**)&ctx->mem, &ctx->bytes, f->r->pool );
        if( rc != APR_SUCCESS ){
            ap_log_rerror( APLOG_MARK, APLOG_ERR, 0, f->r, "failed to apr_bucket_read(): %s", apr_strerror( rc, strbuf, MAX_STRING_LEN ) );
            APR_BRIGADE_INSERT_TAIL( ctx->bb, ap_bucket_error_create( HTTP_INTERNAL_SERVER_ERROR, strbuf, f->r->pool, f->c->bucket_alloc ) );
        }
        // render
        else if( ctx->bytes && ( pass = bp_out( ctx ) ) ){
            apr_brigade_destroy( ctx->bb );
            ctx->bb = pass;
        }
        */
        rc = ap_pass_brigade( f->next, pass );
        apr_brigade_cleanup( pass );
        ap_remove_output_filter( f );
    }
    else {
        rc = ap_pass_brigade( f->next, pass );
        apr_brigade_cleanup( pass );
    }
    
    
    return rc;
}

static int bp_output_filter_setup( ap_filter_t *f )
{
    // int rc = APR_SUCCESS;
    bpServer_cfg *cfg = GET_MODULE_CONFIG( f->r->server->module_config );
    
    if( cfg )
    {
        const char *errstr = NULL;
        
        // temporary delete ETag
        apr_table_unset( f->r->headers_out, "ETag" );
        apr_table_unset( f->r->headers_in, "If-Modified-Since" );
        if( errstr ){
            BP_RERROR( f->r, APLOG_ERR, "%s", errstr );
        }
    }
    
    return APR_SUCCESS;
}


static void bp_insert_filter( request_rec *r )
{
    // insert output filter when error occurred
    if( ap_is_HTTP_ERROR( r->status ) ){
        ap_add_output_filter( BP_OUTPUT_FILTER_NAME, NULL, r, r->connection );
    }
}

/* MARK: Post Config */
static int bp_post_config( apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rc;
    void *tmp = NULL;
    
    if( ( rc = apr_pool_userdata_get( &tmp, PRODUCT_NAME, s->process->pool ) ) ){
        BP_SERROR( s, APLOG_ERR, "failed to apr_pool_userdata_get(): %s", BP_APR_STRERROR( rc ) );
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    else if( !tmp )
    {
        if( ( rc = apr_pool_userdata_set( (void*)1, PRODUCT_NAME, NULL, s->process->pool ) ) ){
            BP_SERROR( s, APLOG_ERR, "failed to apr_pool_userdata_set(): %s", BP_APR_STRERROR( rc ) );
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    else{
        ap_add_version_component( p, PRODUCT_NAME PRODUCT_VERSION 
            " with apr/" APR_VERSION_STRING " apr-util/" APU_VERSION_STRING );
    }
    
    return rc;
}


/* MARK: Configuration */
static void bp_register_hooks( apr_pool_t *p )
{
    ap_hook_post_config( bp_post_config, NULL, NULL, APR_HOOK_MIDDLE );
    // filter
    ap_hook_insert_filter( bp_insert_filter, NULL, NULL, APR_HOOK_MIDDLE );
    ap_hook_insert_error_filter( bp_insert_filter, NULL, NULL, APR_HOOK_FIRST );
    ap_register_output_filter( BP_OUTPUT_FILTER_NAME, bp_output_filter, bp_output_filter_setup, AP_FTYPE_RESOURCE );
}


static void *create_server_config( apr_pool_t *p, server_rec *server )
{
    bpServer_cfg *cfg = NULL;
    apr_status_t rc = APR_SUCCESS;
    apr_pool_t *sp = NULL;
    char *pattern = "<!--[\\t\\s]{0,}Blueprint:[\\t\\n\\s]{0,}(.*?)[\\t\\n\\s]{0,}:-->";
    OnigErrorInfo einfo;
    
    // create sub-pool
    if( ( rc = apr_pool_create( &sp, p ) ) ){
        BP_SERROR( server, APLOG_ERR, "failed to apr_pool_create(): %s", BP_APR_STRERROR( rc ) );
    }
    // allocate bpServer_cfg
    else if( !( cfg = apr_pcalloc( sp, sizeof( bpServer_cfg ) ) ) ){
        BP_SERROR( server, APLOG_ERR, "failed to apr_pcalloc(): %s", BP_APR_STRERROR( APR_ENOMEM ) );
        apr_pool_destroy( sp );
    }
    // create regex for inline Blueprint Dataset
    else if( ( rc = onig_new( &cfg->regexp, (unsigned char*)pattern, (unsigned char*)pattern + strlen( pattern ), 
                            ONIG_OPTION_MULTILINE, ONIG_ENCODING_UTF8, ONIG_SYNTAX_PERL, &einfo ) ) != ONIG_NORMAL ){
        unsigned char strbuf[ONIG_MAX_ERROR_MESSAGE_LEN];
        onig_error_code_to_str( strbuf, rc, &einfo );
        BP_SERROR( server, APLOG_ERR, "failed to onig_new(): %s", strbuf );
        apr_pool_destroy( sp );
        cfg = NULL;
    }
    else {
        cfg->p = sp;
        cfg->tag = BP_DEFAULT_TAGNAME;
        apr_pool_cleanup_register( cfg->p, (void*)cfg, CleanupServerCfg, CleanupServerCfg );
    }
    
    return cfg;
}

static void *merge_server_config( apr_pool_t *p, void *parent_conf, void *newloc_conf )
{
    bpServer_cfg *merged = (bpServer_cfg*)apr_pcalloc( p, sizeof( bpServer_cfg ) );
    bpServer_cfg *parent = (bpServer_cfg*)parent_conf;
    bpServer_cfg *child = (bpServer_cfg*)newloc_conf;
    
    merged->p = p;
    merged->regexp = ( child->regexp ) ? child->regexp : parent->regexp;
    
    return (void*)merged;
}


/* MARK: Command Directive */
static const char *cmd_set_tag( cmd_parms *cmd, void *mconfig, const char *tag )
{
    bpServer_cfg *cfg = GET_MODULE_CONFIG( cmd->server->module_config );
    const char *errstr = NULL;
    
    if( cfg )
    {
        char *ptr = (char*)tag;
        
        if( !isalpha( *ptr ) ){
            errstr = apr_psprintf( cfg->p, "%s: invalid tagname %s", cmd->cmd->name, tag );
        }
        else
        {
            for(; *ptr != '\0'; ptr++ )
            {
                if( !isalnum( *ptr ) ){
                    errstr = apr_psprintf( cfg->p, "%s: invalid tagname %s", cmd->cmd->name, tag );
                    break;
                }
            }
        }
        if( !errstr ){
            cfg->tag = apr_pstrdup( cfg->p, tag );
        }
    }
    
    return errstr;
}

static const command_rec bp_cmds[] =
{
    AP_INIT_TAKE1( 
        "BlueprintTagName", 
        cmd_set_tag, 
        NULL, 
        RSRC_CONF|ACCESS_CONF, 
        "tagname"
    ),
    { NULL }
};

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA blueprint_module = {
    STANDARD20_MODULE_STUFF, 
    NULL,                       /* create per-dir    config structures */
    NULL,                       /* merge  per-dir    config structures */
    create_server_config,       /* create per-server config structures */
    merge_server_config,        /* merge  per-server config structures */
    bp_cmds,                    /* table of config file commands       */
    bp_register_hooks           /* register hooks                      */
};

