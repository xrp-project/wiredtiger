#!/usr/bin/env python
#
# Public Domain 2014-present MongoDB, Inc.
# Public Domain 2008-2014 WiredTiger, Inc.
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import wiredtiger, wttest, os.path
FileSystem = wiredtiger.FileSystem  # easy access to constants

# test_s3_store01.py
#    Test the s3 storage source's file system implementation.
# Note that the APIs we are testing are not meant to be used directly
# by any WiredTiger application, these APIs are used internally.
# However, it is useful to do tests of this API independently.
class test_s3_store01(wttest.WiredTigerTestCase):
    # Load the local store extension.
    def conn_extensions(self, extlist):
        # Windows doesn't support dynamically loaded extension libraries.
        if os.name == 'nt':
            extlist.skip_if_missing = True
        extlist.extension('storage_sources', 's3_store')

    def breakpoint(self):
        import pdb, sys
        sys.stdin = open('/dev/tty', 'r')
        sys.stdout = open('/dev/tty', 'w')
        sys.stderr = open('/dev/tty', 'w')
        pdb.set_trace()

    def get_s3_storage_source(self):
        return self.conn.get_storage_source('s3_store')

    def test_s3_basic(self):
        # Test some basic functionality of the storage source API, calling
        # each supported method in the API at least once.

        session = self.session
        s3 = self.get_s3_storage_source()

        fs = s3.ss_customize_file_system(session, "testwtbucket101", "secret", None)

        cachePath = 'cache-testwtbucket101/foobar'

        # The object doesn't exist yet in cloud or in cache.
        dir_ls = fs.fs_directory_list(session, '', '')
        self.assertFalse('foobar' in dir_ls)
        self.assertFalse(os.path.isfile(cachePath))

        # We cannot use the file system to create files, it is readonly.
        # So use python I/O to build up the file.
        f = open('foobar', 'wb')

        # The object still doesn't exist yet in cloud or in cache.
        dir_ls = fs.fs_directory_list(session, '', '')
        self.assertFalse('foobar' in dir_ls)
        self.assertFalse(os.path.isfile(cachePath))

        outbytes = ('MORE THAN ENOUGH DATA\n'*100).encode()
        f.write(outbytes)
        f.close()

        # The object still doesn't exist until a flush.
        dir_ls = fs.fs_directory_list(session, '', '')
        self.assertFalse('foobar' in dir_ls)
        self.assertFalse(os.path.isfile(cachePath))

        # Flushing copies the file into the file system.
        s3.ss_flush(session, fs, 'foobar', 'foobar', None)
        # The object exists now in the cloud.
        dir_ls = fs.fs_directory_list(session, '', '')
        self.assertTrue('foobar' in dir_ls)
        # and now in the cache
        s3.ss_flush_finish(session, fs, 'foobar', 'foobar', None)
        self.assertTrue(os.path.isfile(cachePath))

        # Lets delete the cached and local file
        os.remove(cachePath)
        os.rename('foobar', 'foobar.bak')
        self.assertFalse(os.path.isfile('foobar'))
        self.assertFalse(os.path.isfile(cachePath))

        # Trying to read the file from s3 storage fs shoulf bring it back to the cache
        fh = fs.fs_open_file(session, 'foobar', FileSystem.open_file_type_data, FileSystem.open_readonly)
        self.assertFalse(os.path.isfile('foobar'))
        self.assertTrue(os.path.isfile(cachePath))

        # Read the file and verify contents
        inbytes = bytes(len(outbytes))
        fh.fh_read(session, 0, inbytes)
        self.assertEquals(inbytes, outbytes)

        # Delete shouldn't be allowed on cloud, but this will clean the bucket for POC.
        fs.fs_remove(session, 'foobar', 0)

        fs.terminate(session)
        s3.terminate(session)

if __name__ == '__main__':
    wttest.run()
