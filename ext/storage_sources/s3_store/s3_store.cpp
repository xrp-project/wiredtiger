/*-
 * Public Domain 2014-present MongoDB, Inc.
 * Public Domain 2008-2014 WiredTiger, Inc.
 *
 * This is free and unencumbered software released into the public domain.
 *
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 *
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <wiredtiger.h>
#include <wiredtiger_ext.h>
#include "queue.h"


#include <aws/core/Aws.h>
#include <aws/core/utils/logging/LogLevel.h>
#include <aws/s3-crt/S3CrtClient.h>
#include <aws/s3-crt/model/ListObjectsRequest.h>
#include <aws/s3-crt/model/PutObjectRequest.h>
#include <aws/s3-crt/model/GetObjectRequest.h>
#include <aws/s3-crt/model/DeleteObjectRequest.h>

#include <iostream>
#include <fstream>
#include <vector>

#ifdef __GNUC__
#if __GNUC__ > 7 || (__GNUC__ == 7 && __GNUC_MINOR__ > 0)
/*
 * !!!
 * GCC with -Wformat-truncation complains about calls to snprintf in this file.
 * There's nothing wrong, this makes the warning go away.
 */
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
#endif

using namespace Aws;
using namespace std;

#define WT_UNUSED(var) (void)(var)
static const char ALLOCATION_TAG[] = "s3-store-poc";
    
//The Aws::SDKOptions struct contains SDK configuration options.
//An instance of Aws::SDKOptions is passed to the Aws::InitAPI and 
//Aws::ShutdownAPI methods.  The same instance should be sent to both methods.
SDKOptions options;

class AWSBucket {
    public:
        AWSBucket(const string& _bucketName)
            : bucketName(_bucketName)
            , client(config) {}
        
        void printBucketList() {
            auto outcome = client.ListBuckets();
            if (outcome.IsSuccess()) {
                cout << "Found " << outcome.GetResult().GetBuckets().size() << " buckets\n";
                for (auto&& b : outcome.GetResult().GetBuckets()) {
                    cout << b.GetName() << endl;
                }
            }
            else {
                cout << "Failed with error: " << outcome.GetError() << endl;
            }
        }

        int listObjects(vector<string>& objKeys, uint32_t limit = 0) {
            /* 
             * Can only fetch 1000 max at a time, need to re-iter to get more:
             * https://docs.aws.amazon.com/AmazonS3/latest/userguide/ListingKeysUsingAPIs.html
             */
            Aws::S3Crt::Model::ListObjectsRequest listObjectsRequest;
            listObjectsRequest.SetBucket(bucketName);
            if (limit != 0)
                listObjectsRequest.SetMaxKeys(limit);

            Aws::S3Crt::Model::ListObjectsOutcome listObjectsOutcome =
               client.ListObjects(listObjectsRequest);

            if (!listObjectsOutcome.IsSuccess())
                return (-1);

            for (const auto& object : listObjectsOutcome.GetResult().GetContents())
                objKeys.push_back(object.GetKey());

            return (0);
        }

        int putObject(const string& objectKey, const string& fileName) {
			Aws::S3Crt::Model::PutObjectRequest request;
			request.SetBucket(bucketName);
			request.SetKey(objectKey);
			
            std::shared_ptr<Aws::IOStream> bodyStream =
			  Aws::MakeShared<Aws::FStream>(ALLOCATION_TAG, fileName.c_str(),
			    ios_base::in | ios_base::binary);
			if (!bodyStream->good())
                return (-1);
			
            request.SetBody(bodyStream);

			//A PUT operation turns into a multipart upload using the s3-crt client.
			//https://github.com/aws/aws-sdk-cpp/wiki/Improving-S3-Throughput-with-AWS-SDK-for-CPP-v1.9
			Aws::S3Crt::Model::PutObjectOutcome outcome = client.PutObject(request);

			if (!outcome.IsSuccess())
                return (-1);

            return (0);
        }

        int getObject(const string& objectKey, const string& dstFileName) {
            Aws::S3Crt::Model::GetObjectRequest request;
            request.SetBucket(bucketName);
            request.SetKey(objectKey);

            Aws::S3Crt::Model::GetObjectOutcome outcome = client.GetObject(request);
			if (!outcome.IsSuccess())
                return (-1);

            auto &retrievedFile = outcome.GetResult().GetBody();
            ofstream opFile(dstFileName.c_str(), ios::out | ios::binary);
            opFile << retrievedFile.rdbuf();

            return (0);
        }

        int deleteObject(const string& objectKey) {
            Aws::S3Crt::Model::DeleteObjectRequest deleteObjectRequest;
            deleteObjectRequest.SetBucket(bucketName);
            deleteObjectRequest.SetKey(objectKey);
            Aws::S3Crt::Model::DeleteObjectOutcome deleteObjectOutcome =
              client.DeleteObject(deleteObjectRequest);

            if (!deleteObjectOutcome.IsSuccess())
                return (-1);

            return (0);
        }

        int deleteAllObjects() {
            vector<string> objKeys;

            if (listObjects(objKeys) != 0)
                return (-1);

            for (auto o : objKeys)
                if (deleteObject(o) != 0)
                    return (-1);

            return (0);
        }

    private:
        const string bucketName;
        
        /* AWS Config */
        Aws::S3Crt::ClientConfiguration config;
        Aws::S3Crt::S3CrtClient client;
};

/* S3 storage source structure. */
typedef struct {
    WT_STORAGE_SOURCE storage_source; /* Must come first */

    WT_EXTENSION_API *wt_api; /* Extension API */

    /*
     * Keep the number of references to this storage source.
     */
    uint32_t reference_count;
} S3_STORAGE;

typedef struct {
    /* Must come first - this is the interface for the file system we are implementing. */
    WT_FILE_SYSTEM file_system;
    /* This is WiredTiger's file system, it is used in implementing the cache local file system. */
    WT_FILE_SYSTEM *wt_fs;
    S3_STORAGE *s3_store;
    AWSBucket *bucket;

    char *auth_token;     /* Identifier for key management system */
    char *bucket_name;    /* cloud storage bucket */
    char *cache_dir;      /* Directory for cached objects */
} S3_FILE_SYSTEM;

typedef struct s3_file_handle {
    WT_FILE_HANDLE iface; /* Must come first */
    WT_FILE_HANDLE *wt_fh;   /* File handle to cached file on local file system. */
    S3_STORAGE *s3_store; /* Enclosing storage source */
} S3_FILE_HANDLE;

/*
 * s3_err --
 *     Print errors from the interface. Returns "ret", the third argument.
 */
static int
s3_err(S3_STORAGE *s3_store, WT_SESSION *session, int ret, const char *format, ...)
{
    va_list ap;
    WT_EXTENSION_API *wt_api;
    char buf[1000];

    va_start(ap, format);
    wt_api = s3_store->wt_api;
    if (vsnprintf(buf, sizeof(buf), format, ap) >= (int)sizeof(buf))
        wt_api->err_printf(wt_api, session, "s3_storage: error overflow");
    wt_api->err_printf(
      wt_api, session, "s3_storage: %s: %s", wt_api->strerror(wt_api, session, ret), buf);
    va_end(ap);

    return (ret);
}

/*
 * s3_add_reference --
 *     Add a reference to the storage source so we can reference count to know when to really
 *     terminate.
 */
static int
s3_add_reference(WT_STORAGE_SOURCE *storage_source)
{
    S3_STORAGE *s3_store;

    s3_store = (S3_STORAGE *)storage_source;

    /*
     * Missing reference or overflow?
     */
    if (s3_store->reference_count == 0 || s3_store->reference_count + 1 == 0)
        return (EINVAL);
    ++s3_store->reference_count;
    return (0);
}

/*
 * s3_free_list_internal --
 *     Internal function to free list
 */
static void
s3_free_list_internal(char ***c_listp, uint32_t *countp)
{
    uint32_t i;
    char **list;

    if (c_listp == NULL || *c_listp == NULL)
        return;

    list = *c_listp;
    for (i = 0; i < *countp && list[i] != NULL; i++)
        free(list[i]);
    free(list);
}

/*
 * s3_vector_to_char_list --
 *     char list from vector
 */
static int
s3_vector_to_char_list(WT_FILE_SYSTEM *file_system, WT_SESSION *session,
  vector<string>& v, char ***c_listp, uint32_t *countp)
{
    S3_FILE_SYSTEM *fs;
    S3_STORAGE *s3_store;
    uint32_t count, i;
    int ret;
    char **list;

    if (c_listp == NULL || countp == NULL)
        return (-1);

    *c_listp = NULL;
    *countp = i = ret = 0;
    count = v.size();

    fs = (S3_FILE_SYSTEM *)file_system;
    s3_store = fs->s3_store;
    
    if ((list = (char **) calloc(count, sizeof(char *))) == NULL) {
        ret = s3_err(s3_store, session, ENOMEM, "s3_vector_to_char_list");
        goto err;
    }
    for (auto s : v) {
        if ((list[i] = strdup(s.c_str())) == NULL) {
            ret = s3_err(s3_store, session, ENOMEM, "s3_vector_to_char_list");
            goto err;
        }
        i++;
    }

    *c_listp = list;
    *countp = count;

    return (0);

err:
    s3_free_list_internal(&list, &count);

    return (ret);
}

/*
 * s3_directory_list_internal --
 *     Return a list of object names for the given location.
 */
static int
s3_directory_list_internal(WT_FILE_SYSTEM *file_system, WT_SESSION *session, const char *directory,
  const char *prefix, char ***dirlistp, uint32_t *countp, uint32_t limit = 0)
{
    S3_FILE_SYSTEM *fs;
    S3_STORAGE *s3_store;
    vector<string> vlist;
    int ret;

    WT_UNUSED(directory);
    WT_UNUSED(prefix);

    fs = (S3_FILE_SYSTEM *)file_system;
    s3_store = fs->s3_store;

    if (fs->bucket->listObjects(vlist, limit) != 0) {
        ret = s3_err(s3_store, session, -1, "s3_directory_list");
        goto err;
    }
    
    if (s3_vector_to_char_list(file_system, session, vlist, dirlistp, countp) != 0) {
        ret = s3_err(s3_store, session, -1, "s3_directory_list");
        goto err;
    }

    return (0);

err:
    s3_free_list_internal(dirlistp, countp);
    return(ret);
}

/*
 * s3_directory_list --
 *     Return a list of object names for the given location.
 */
static int
s3_directory_list(WT_FILE_SYSTEM *file_system, WT_SESSION *session, const char *directory,
  const char *prefix, char ***dirlistp, uint32_t *countp)
{
    return (s3_directory_list_internal(file_system, session, directory, prefix, dirlistp, countp));
}

/*
 * s3_directory_list_single --
 *     Return a single file name for the given location.
 */
static int
s3_directory_list_single(WT_FILE_SYSTEM *file_system, WT_SESSION *session, const char *directory,
  const char *prefix, char ***dirlistp, uint32_t *countp)
{
    return (s3_directory_list_internal(
      file_system, session, directory, prefix, dirlistp, countp, 1));
}

/*
 * s3_location_list_free --
 *     Free memory allocated by local_location_list.
 */
static int
s3_directory_list_free(
  WT_FILE_SYSTEM *file_system, WT_SESSION *session, char **dirlist, uint32_t count)
{
    WT_UNUSED(file_system);
    WT_UNUSED(session);

    s3_free_list_internal(&dirlist, &count);
    return (0);
}

/*
 * local_get_directory --
 *     For caching locally, return a copy of a directory name after verifying that it is a directory.
 */
static int
local_get_directory(const char *home, const char *s, ssize_t len, bool create, char **copy)
{
    struct stat sb;
    size_t buflen;
    int ret;
    char *dirname;

    *copy = NULL;

    if (len == -1)
        len = (ssize_t)strlen(s);

    /* For relative pathnames, the path is considered to be relative to the home directory. */
    if (*s == '/')
        dirname = strndup(s, (size_t)len + 1); /* Room for null */
    else {
        buflen = (size_t)len + strlen(home) + 2; /* Room for slash, null */
        if ((dirname = (char *) malloc(buflen)) != NULL)
            if (snprintf(dirname, buflen, "%s/%.*s", home, (int)len, s) >= (int)buflen)
                return (EINVAL);
    }
    if (dirname == NULL)
        return (ENOMEM);

    ret = stat(dirname, &sb);
    if (ret != 0 && errno == ENOENT && create) {
        (void)mkdir(dirname, 0777);
        ret = stat(dirname, &sb);
    }
    if (ret != 0)
        ret = errno;
    else if ((sb.st_mode & S_IFMT) != S_IFDIR)
        ret = EINVAL;
    if (ret != 0)
        free(dirname);
    else
        *copy = dirname;
    return (ret);
}

/*
 * s3_remove --
 *   Shouldnt be suported for cloud objects, but use it to clean the bucket for now.
 */
static int
s3_remove(WT_FILE_SYSTEM *file_system, WT_SESSION *session, const char *name, uint32_t flags)
{
    S3_FILE_SYSTEM *fs;

    WT_UNUSED(session);
    WT_UNUSED(flags);
    
    fs = (S3_FILE_SYSTEM *)file_system;
    return (fs->bucket->deleteObject(name));
}

/*
 * s3_fs_terminate --
 *     Discard any resources on termination of the file system
 */
static int
s3_fs_terminate(WT_FILE_SYSTEM *file_system, WT_SESSION *session)
{
    S3_FILE_SYSTEM *fs;

    WT_UNUSED(session);

    fs = (S3_FILE_SYSTEM *)file_system;

    free(fs->auth_token);
    free(fs->bucket_name);
    free(fs->cache_dir);
    delete fs->bucket;
    free(file_system);

    return (0);
}

/*
 * local_file_read --
 *     POSIX pread - read of cached file on local file system.
 */
static int
local_file_read(
  WT_FILE_HANDLE *file_handle, WT_SESSION *session, wt_off_t offset, size_t len, void *buf)
{
    S3_FILE_HANDLE *fh;
    WT_FILE_HANDLE *wt_fh;

    fh = (S3_FILE_HANDLE *)file_handle;
    wt_fh = fh->wt_fh;

    return (wt_fh->fh_read(wt_fh, session, offset, len, buf));
}

/*
 * s3_open --
 *     fopen for s3 storage source
 */
static int
s3_open(WT_FILE_SYSTEM *file_system, WT_SESSION *session, const char *name,
  WT_FS_OPEN_FILE_TYPE file_type, uint32_t flags, WT_FILE_HANDLE **file_handlep)
{
    S3_FILE_HANDLE *fh;
    S3_FILE_SYSTEM *fs;
    S3_STORAGE *s3_store;
    WT_FILE_HANDLE *file_handle, *wt_fh;
    WT_FILE_SYSTEM *wt_fs;
    struct stat sb;
    int ret;
    string cachePath;
    
    *file_handlep = NULL;

    fh = NULL;
    fs = (S3_FILE_SYSTEM *)file_system;
    s3_store = fs->s3_store;
    ret = 0;
    wt_fs = fs->wt_fs;

    if ((flags & WT_FS_OPEN_READONLY) == 0 || (flags & WT_FS_OPEN_CREATE) != 0)
        return (
          s3_err(s3_store, session, EINVAL, "ss_open_object: readonly access required: %s", name));

    /* Create a new handle. */
    if ((fh = (S3_FILE_HANDLE *)calloc(1, sizeof(S3_FILE_HANDLE))) == NULL) {
        ret = ENOMEM;
        goto err;
    }

    /* Path to file in local cache */
    cachePath = string(fs->cache_dir) + string("/") + string(name);

    /* If the file doersnt exist locally, bring it in from the cloud. */
    ret = stat(cachePath.c_str(), &sb);
    if (ret != 0) {
        if (errno != ENOENT) {
            ret = s3_err(s3_store, session, errno, "%s: s3_open stat", cachePath.c_str());
            goto err;
        }

        /*
         * The file doesn't exist in the cache, make a copy of it from the cloud.
         */
        if ((ret = fs->bucket->getObject(name, cachePath)) != 0) {
            ret = s3_err(s3_store, session, errno,
              "%s: s3_open getObject failed", cachePath.c_str());
            goto err;
        }
    }
    if ((ret = wt_fs->fs_open_file(wt_fs, session,
      cachePath.c_str(), file_type, flags, &wt_fh)) != 0) {
        ret = s3_err(s3_store, session, ret, "ss_open_object: open: %s", name);
        goto err;
    }
    fh->wt_fh = wt_fh;
    fh->s3_store = s3_store;

    /* Initialize public information. */
    file_handle = (WT_FILE_HANDLE *)fh;

    /*
     * Setup the function call table for our custom storage source. Set the function pointer to NULL
     * where our implementation doesn't support the functionality.
     */
    file_handle->close = NULL;
    file_handle->fh_advise = NULL;
    file_handle->fh_extend = NULL;
    file_handle->fh_extend_nolock = NULL;
    file_handle->fh_lock = NULL;
    file_handle->fh_map = NULL;
    file_handle->fh_map_discard = NULL;
    file_handle->fh_map_preload = NULL;
    file_handle->fh_unmap = NULL;
    file_handle->fh_read = local_file_read;
    file_handle->fh_size = NULL;
    file_handle->fh_sync = NULL;
    file_handle->fh_sync_nowait = NULL;
    file_handle->fh_truncate = NULL;
    file_handle->fh_write = NULL;
    if ((file_handle->name = strdup(name)) == NULL) {
        ret = ENOMEM;
        goto err;
    }

    *file_handlep = file_handle;

err:
    if (ret != 0) {
        if (fh != NULL) {
            if (fh->wt_fh != NULL)
                (void) fh->wt_fh->close(fh->wt_fh, session);
            free(fh->iface.name);
            free(fh);
        }
    }
    return (ret);
}

/*
 * s3_customize_file_system --
 *     Return a customized file system to access the s3 storage source objects.
 */
static int
s3_customize_file_system(WT_STORAGE_SOURCE *storage_source, WT_SESSION *session,
  const char *bucket_name, const char *auth_token, const char *config,
  WT_FILE_SYSTEM **file_systemp)
{
    S3_STORAGE *s3_store;
    S3_FILE_SYSTEM *fs;
    WT_CONFIG_ITEM cachedir;
    WT_FILE_SYSTEM *wt_fs;
    int ret;
    const char *p;
    char buf[1024];
    const char *home_dir; /* Owned by the connection */

    const string bucketStr(bucket_name);
    s3_store = (S3_STORAGE *)storage_source;

    fs = NULL;
    ret = 0;

    /* Parse configuration string. */
    if ((ret = s3_store->wt_api->config_get_string(
           s3_store->wt_api, session, config, "cache_directory", &cachedir)) != 0) {
        if (ret == WT_NOTFOUND) {
            ret = 0;
            cachedir.len = 0;
        } else {
            ret = s3_err(s3_store, session, ret, "customize_file_system: config parsing");
            goto err;
        }
    }

    if ((ret = s3_store->wt_api->file_system_get(s3_store->wt_api, session, &wt_fs)) != 0) {
        ret = s3_err(s3_store, session, ret, "s3_file_system: cannot get WiredTiger file system");
        goto err;
    }
    if ((fs = (S3_FILE_SYSTEM *) calloc(1, sizeof(S3_FILE_SYSTEM))) == NULL) {
        ret = s3_err(s3_store, session, ENOMEM, "s3_file_system");
        goto err;
    }
    fs->s3_store = s3_store;
    fs->wt_fs = wt_fs;

    if ((fs->auth_token = strdup(auth_token)) == NULL) {
        ret = s3_err(s3_store, session, ENOMEM, "s3_file_system.auth_token");
        goto err;
    }

    if ((fs->bucket_name = strdup(bucket_name)) == NULL) {
        ret = s3_err(s3_store, session, ENOMEM, "s3_file_system.bucket_name");
        goto err;
    }

    // Not handling allocation failures for now.
    fs->bucket = new AWSBucket(bucketStr);

    /*
     * The home directory owned by the connection will not change, and will be valid memory, for as
     * long as the connection is open. That is longer than this file system will be open, so we can
     * use the string without copying.
     */
    home_dir = session->connection->get_home(session->connection);

    /*
     * Get the cache directory.
     * The default cache directory is named "cache-<name>", where name is the last component of the
     * bucket name's path. We'll create it if it doesn't exist.
     */
    if (cachedir.len == 0) {
        if ((p = strrchr(bucket_name, '/')) != NULL)
            p++;
        else
            p = bucket_name;
        if (snprintf(buf, sizeof(buf), "cache-%s", p) >= (int)sizeof(buf)) {
            ret = s3_err(s3_store, session, EINVAL, "overflow snprintf");
            goto err;
        }
        cachedir.str = buf;
        cachedir.len = strlen(buf);
    }
    if ((ret = local_get_directory(
           home_dir, cachedir.str, (ssize_t)cachedir.len, true, &fs->cache_dir)) != 0) {
        ret =
          s3_err(s3_store, session, ret, "%*s: cache directory", (int)cachedir.len, cachedir.str);
        goto err;
    }
    fs->file_system.fs_directory_list = s3_directory_list;
    fs->file_system.fs_directory_list_single = s3_directory_list_single;
    fs->file_system.fs_directory_list_free = s3_directory_list_free;
    fs->file_system.terminate = s3_fs_terminate;
    fs->file_system.fs_remove = s3_remove;
    fs->file_system.fs_open_file = s3_open;
    fs->file_system.fs_exist = NULL;
    fs->file_system.fs_rename = NULL;
    fs->file_system.fs_size = NULL;
err:
    if (ret == 0)
        *file_systemp = &fs->file_system;
    else if (fs != NULL) {
        free(fs->auth_token);
        free(fs->bucket_name);
        free(fs->cache_dir);
        delete fs->bucket;
        free(fs);
    }
    return (ret);
}

/*
 * s3_flush --
 *     Return when the file has been flushed.
 */
static int
s3_flush(WT_STORAGE_SOURCE *storage_source, WT_SESSION *session, WT_FILE_SYSTEM *file_system,
  const char *source, const char *object, const char *config)
{
    S3_STORAGE *s3_store;
    S3_FILE_SYSTEM *fs;
    int ret;

    WT_UNUSED(config);

    s3_store = (S3_STORAGE *)storage_source;
    fs = (S3_FILE_SYSTEM *)file_system;

    if (file_system == NULL || source == NULL || object == NULL)
        return s3_err(s3_store, session, EINVAL, "ss_flush: required arguments missing");

    if (fs->bucket->putObject(object, source) != 0) {
        ret = s3_err(s3_store, session, -1, "s3_flush");
        return(ret);
    }

	return (0);
}
	
/*
 * s3_flush_finish --
 *     Cache a file in the new file system.
 */
static int
s3_flush_finish(WT_STORAGE_SOURCE *storage_source, WT_SESSION *session,
  WT_FILE_SYSTEM *file_system, const char *source, const char *object, const char *config)
{
    S3_STORAGE *s3_store;
    S3_FILE_SYSTEM *fs;
    int ret;
    string dstPath;
	
	WT_UNUSED(session);
	WT_UNUSED(object);
	WT_UNUSED(config);

    s3_store = (S3_STORAGE *)storage_source;
    fs = (S3_FILE_SYSTEM *)file_system;

    if (file_system == NULL || source == NULL || object == NULL)
        return s3_err(s3_store, session, EINVAL, "ss_flush: required arguments missing");

    dstPath = string(fs->cache_dir) + string("/") + string(source);

    /*
     * Link the object with the original local object. The could be replaced by a file copy if
     * portability is an issue.
     */
    if ((ret = link(source, dstPath.c_str())) != 0) {
        ret = s3_err(s3_store, session, errno,
          "ss_flush_finish link %s to %s failed", source, dstPath.c_str());
        return (ret);
    }
    /* Set the file to readonly in the cache. */
    if (ret = chmod(dstPath.c_str(), 0444) < 0) {
        ret = s3_err(s3_store, session, errno, "%s: ss_flush_finish chmod failed", dstPath.c_str());
        return (ret);
    }

	return (0);
}

/*
 * s3_terminate --
 *     Discard any resources on termination
 */
static int
s3_terminate(WT_STORAGE_SOURCE *storage, WT_SESSION *session)
{
    S3_STORAGE *s3_store;
    int ret;

    ret = 0;

    s3_store = (S3_STORAGE *)storage;

    if (--s3_store->reference_count != 0)
        return (0);
            
    //Before the application terminates, the SDK must be shut down. 
    ShutdownAPI(options);

    free(s3_store);
    return (ret);
}

/*
 * wiredtiger_extension_init --
 *     A simple shared library encryption example.
 */
int
wiredtiger_extension_init(WT_CONNECTION *connection, WT_CONFIG_ARG *config)
{
    S3_STORAGE *s3_store;
    int ret;

    if ((s3_store = (S3_STORAGE *)calloc(1, sizeof(S3_STORAGE))) == NULL)
        return (errno);
    s3_store->wt_api = connection->get_extension_api(connection);

    /*
     * Allocate a S3 storage structure, with a WT_STORAGE structure as the first field, allowing
     * us to treat references to either type of structure as a reference to the other type.
     */
    s3_store->storage_source.ss_add_reference = s3_add_reference;
    s3_store->storage_source.ss_customize_file_system = s3_customize_file_system;
    s3_store->storage_source.ss_flush = s3_flush;
    s3_store->storage_source.ss_flush_finish = s3_flush_finish;
    s3_store->storage_source.terminate = s3_terminate;

    /*
     * The first reference is implied by the call to add_storage_source.
     */
    s3_store->reference_count = 1;
    
    options.loggingOptions.logLevel = Utils::Logging::LogLevel::Debug;
    //The AWS SDK for C++ must be initialized by calling Aws::InitAPI.
    InitAPI(options); 
        
    /* Load the storage */
    if ((ret = connection->add_storage_source(
           connection, "s3_store", &s3_store->storage_source, NULL)) != 0) {
        (void)s3_err(s3_store, NULL, ret, "WT_CONNECTION->add_storage_source");
        free(s3_store);
    }

    return (ret);
}
