﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Permissions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Common;
using Microsoft.Data.SqlClient;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.Data.SqlTypes
{
    /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/SqlFileStream/*' />
    public sealed partial class SqlFileStream : System.IO.Stream
    {
        // NOTE: if we ever unseal this class, be sure to specify the Name, SafeFileHandle, and
        // TransactionContext accessors as virtual methods. Doing so now on a sealed class
        // generates a compiler error (CS0549)

        private static int s_objectTypeCount; // EventSource Counter
        internal int ObjectID { get; } = Interlocked.Increment(ref s_objectTypeCount);

        // from System.IO.FileStream implementation
        // DefaultBufferSize = 4096;
        // SQLBUVSTS# 193123 - disable lazy flushing of written data in order to prevent
        // potential exceptions during Close/Finalization. Since System.IO.FileStream will
        // not allow for a zero byte buffer, we'll create a one byte buffer which, in normal
        // usage, will not be used and the user buffer will automatically flush directly to
        // the disk cache. In pathological scenarios where the client is writing a single
        // byte at a time, we'll explicitly call flush ourselves.
        private const int DefaultBufferSize = 1;

        private const ushort IoControlCodeFunctionCode = 2392;
        private const int ERROR_MR_MID_NOT_FOUND = 317;
        #region Definitions from devioctl.h
        private const ushort FILE_DEVICE_FILE_SYSTEM = 0x0009;
        #endregion

        private System.IO.FileStream _fs;
        private string _path;
        private byte[] _txn;
        private bool _disposed;
        private static ReadOnlySpan<byte> EaNameString => new byte[]
        {
            (byte)'F', (byte)'i', (byte)'l', (byte)'e', (byte)'s', (byte)'t', (byte)'r', (byte)'e', (byte)'a', (byte)'m', (byte)'_',
            (byte)'T', (byte)'r', (byte)'a', (byte)'n', (byte)'s', (byte)'a', (byte)'c', (byte)'t', (byte)'i', (byte)'o', (byte)'n', (byte)'_',
            (byte)'T', (byte)'a', (byte)'g', (byte) '\0'
        };

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ctor1/*' />
        public SqlFileStream(string path, byte[] transactionContext, FileAccess access) :
            this(path, transactionContext, access, FileOptions.None, 0)
        { }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ctor2/*' />
        public SqlFileStream(string path, byte[] transactionContext, FileAccess access, FileOptions options, long allocationSize)
        {
            using (TryEventScope.Create(SqlClientEventSource.Log.TryScopeEnterEvent("SqlFileStream.ctor | API | Object Id {0} | Access {1} | Options {2} | Path '{3}'", ObjectID, (int)access, (int)options, path)))
            {
                //-----------------------------------------------------------------
                // precondition validation

                if (transactionContext == null)
                {
                    throw ADP.ArgumentNull("transactionContext");
                }

                if (path == null)
                {
                    throw ADP.ArgumentNull("path");
                }

                //-----------------------------------------------------------------

                _disposed = false;
                _fs = null;

                OpenSqlFileStream(path, transactionContext, access, options, allocationSize);

                // only set internal state once the file has actually been successfully opened
                Name = path;
                TransactionContext = transactionContext;
            }
        }

        #region destructor/dispose code

        // NOTE: this destructor will only be called only if the Dispose
        // method is not called by a client, giving the class a chance
        // to finalize properly (i.e., free unmanaged resources)
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/dtor/*' />
        ~SqlFileStream()
        {
            Dispose(false);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Dispose/*' />
        protected override void Dispose(bool disposing)
        {
            try
            {
                if (!_disposed)
                {
                    try
                    {
                        if (disposing)
                        {
                            if (_fs != null)
                            {
                                _fs.Close();
                                _fs = null;
                            }
                        }
                    }
                    finally
                    {
                        _disposed = true;
                    }
                }
            }
            finally
            {
                base.Dispose(disposing);
            }
        }
        #endregion

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Name/*' />
        public string Name
        {
            get
            {
                // assert that path has been properly processed via GetFullPathInternal
                // (e.g. m_path hasn't been set directly)
                AssertPathFormat(_path);
                return _path;
            }
#if NETFRAMEWORK
            [ResourceExposure(ResourceScope.None)] // SxS: the file name is not exposed
            [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
#endif
            private set
            {
                // should be validated by callers of this method
                Debug.Assert(value != null);
                Debug.Assert(!_disposed);

                _path = GetFullPathInternal(value);
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/TransactionContext/*' />
        public byte[] TransactionContext
        {
            get
            {
                if (_txn == null)
                    return null;

                return (byte[])_txn.Clone();
            }
            private set
            {
                // should be validated by callers of this method
                Debug.Assert(value != null);
                Debug.Assert(!_disposed);

                _txn = (byte[])value.Clone();
            }
        }

        #region System.IO.Stream methods

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/CanRead/*' />
        public override bool CanRead
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.CanRead;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/CanSeek/*' />
        // If CanSeek is false, Position, Seek, Length, and SetLength should throw.
        public override bool CanSeek
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.CanSeek;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/CanTimeout/*' />
        public override bool CanTimeout
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.CanTimeout;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/CanWrite/*' />
        public override bool CanWrite
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.CanWrite;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Length/*' />
        public override long Length
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.Length;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Position/*' />
        public override long Position
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.Position;
            }
            set
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                _fs.Position = value;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ReadTimeout/*' />
#if NETFRAMEWORK
        [ComVisible(false)]
#endif
        public override int ReadTimeout
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.ReadTimeout;
            }
            set
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                _fs.ReadTimeout = value;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/WriteTimeout/*' />
#if NETFRAMEWORK
        [ComVisible(false)]
#endif
        public override int WriteTimeout
        {
            get
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                return _fs.WriteTimeout;
            }
            set
            {
                if (_disposed)
                    throw ADP.ObjectDisposed(this);

                _fs.WriteTimeout = value;
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Flush/*' />
        public override void Flush()
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            _fs.Flush();
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/BeginRead/*' />
#if !NET6_0_OR_GREATER
        [HostProtection(ExternalThreading = true)]
#endif
        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.BeginRead(buffer, offset, count, callback, state);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/EndRead/*' />
        public override int EndRead(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.EndRead(asyncResult);
        }

#if !NETSTANDARD2_0 && !NETFRAMEWORK
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ReadAsync1/*' />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.ReadAsync(buffer, cancellationToken);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ReadAsync2/*' />
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.ReadAsync(buffer, offset, count, cancellationToken);
        }
#endif

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/BeginWrite/*' />
#if !NET6_0_OR_GREATER
        [HostProtection(ExternalThreading = true)]
#endif
        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            IAsyncResult asyncResult = _fs.BeginWrite(buffer, offset, count, callback, state);

            // SQLBUVSTS# 193123 - disable lazy flushing of written data in order to prevent
            // potential exceptions during Close/Finalization. Since System.IO.FileStream will
            // not allow for a zero byte buffer, we'll create a one byte buffer which, in normal
            // usage, will not be used and the user buffer will automatically flush directly to
            // the disk cache. In pathological scenarios where the client is writing a single
            // byte at a time, we'll explicitly call flush ourselves.
            if (count == 1)
            {
                // calling flush here will mimic the internal control flow of System.IO.FileStream
                _fs.Flush();
            }

            return asyncResult;
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/EndWrite/*' />
        public override void EndWrite(IAsyncResult asyncResult)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            _fs.EndWrite(asyncResult);
        }

#if !NETSTANDARD2_0 && !NETFRAMEWORK
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/WriteAsync1/*' />
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.WriteAsync(buffer, cancellationToken);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/WriteAsync2/*' />
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.WriteAsync(buffer, offset, count, cancellationToken);
        }
#endif

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Seek/*' />
        public override long Seek(long offset, SeekOrigin origin)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.Seek(offset, origin);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/SetLength/*' />
        public override void SetLength(long value)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            _fs.SetLength(value);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Read/*' />
        public override int Read([In, Out] byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.Read(buffer, offset, count);
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/ReadByte/*' />
        public override int ReadByte()
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            return _fs.ReadByte();
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/Write/*' />
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            _fs.Write(buffer, offset, count);

            // SQLBUVSTS# 193123 - disable lazy flushing of written data in order to prevent
            // potential exceptions during Close/Finalization. Since System.IO.FileStream will
            // not allow for a zero byte buffer, we'll create a one byte buffer which, in normal
            // usage, will cause System.IO.FileStream to utilize the user-supplied buffer and
            // automatically flush the data directly to the disk cache. In pathological scenarios
            // where the user is writing a single byte at a time, we'll explicitly call flush ourselves.
            if (count == 1)
            {
                // calling flush here will mimic the internal control flow of System.IO.FileStream
                _fs.Flush();
            }
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlTypes/SqlFileStream.xml' path='docs/members[@name="SqlFileStream"]/WriteByte/*' />
        public override void WriteByte(byte value)
        {
            if (_disposed)
                throw ADP.ObjectDisposed(this);

            _fs.WriteByte(value);

            // SQLBUVSTS# 193123 - disable lazy flushing of written data in order to prevent
            // potential exceptions during Close/Finalization. Since our internal buffer is
            // only a single byte in length, the provided user data will always be cached.
            // As a result, we need to be sure to flush the data to disk ourselves.

            // calling flush here will mimic the internal control flow of System.IO.FileStream
            _fs.Flush();
        }

        #endregion

        static private readonly char[] s_invalidPathChars = Path.GetInvalidPathChars();

        // path length limitations:
        // 1. path length storage (in bytes) in UNICODE_STRING is limited to UInt16.MaxValue bytes = Int16.MaxValue chars
        // 2. GetFullPathName API of kernel32 does not accept paths with length (in chars) greater than 32766
        //    (32766 is actually Int16.MaxValue - 1, while (-1) is for NULL termination)
        // We must check for the lowest value between the the two
        private const int MaxWin32PathLength = short.MaxValue - 1;

        [Conditional("DEBUG")]
        static private void AssertPathFormat(string path)
        {
            Debug.Assert(path != null);
            Debug.Assert(path == path.Trim());
            Debug.Assert(path.Length > 0);
            Debug.Assert(path.Length <= MaxWin32PathLength);
            Debug.Assert(path.IndexOfAny(s_invalidPathChars) < 0);
            Debug.Assert(path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase));
            Debug.Assert(!System.IO.PathInternal.IsDevice(path.AsSpan()));
        }

#if NETFRAMEWORK
        [ResourceExposure(ResourceScope.Machine)]
        [ResourceConsumption(ResourceScope.Machine)]
#endif
        static private string GetFullPathInternal(string path)
        {
            //-----------------------------------------------------------------
            // precondition validation should be validated by callers of this method
            // NOTE: if this method moves elsewhere, this assert should become an actual runtime check
            // as the implicit assumptions here cannot be relied upon in an inter-class context
            Debug.Assert(path != null);

            // remove leading and trailing whitespace
            path = path.Trim();
            if (path.Length == 0)
            {
                throw ADP.Argument(StringsHelper.GetString(StringsHelper.SqlFileStream_InvalidPath), "path");
            }

            // check for the path length before we normalize it with GetFullPathName
            if (path.Length > MaxWin32PathLength)
            {
                // cannot use PathTooLongException here since our length limit is 32K while
                // PathTooLongException error message states that the path should be limited to 260
                throw ADP.Argument(StringsHelper.GetString(StringsHelper.SqlFileStream_InvalidPath), "path");
            }

            // GetFullPathName does not check for invalid characters so we still have to validate them before
            if (path.IndexOfAny(s_invalidPathChars) >= 0)
            {
                throw ADP.Argument(StringsHelper.GetString(StringsHelper.SqlFileStream_InvalidPath), "path");
            }

            // make sure path is not DOS device path
            if (!path.StartsWith(@"\\", StringComparison.Ordinal) && !System.IO.PathInternal.IsDevice(path.AsSpan()))
            {
                throw ADP.Argument(StringsHelper.GetString(Strings.SqlFileStream_InvalidPath), "path");
            }

            // normalize the path
            path = System.IO.Path.GetFullPath(path);

            // we do not expect windows API to return invalid paths
            Debug.Assert(path.Length <= MaxWin32PathLength, "GetFullPathName returns path longer than max expected!");

            // make sure path is a UNC path
            if (System.IO.PathInternal.IsDeviceUNC(path.AsSpan()))
            {
                throw ADP.Argument(StringsHelper.GetString(Strings.SqlFileStream_PathNotValidDiskResource), "path");
            }

            return path;
        }

#if NETFRAMEWORK
        // SxS: SQL File Stream is a database resource, not a local machine one
        [ResourceExposure(ResourceScope.None)]
        [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
#endif
        private unsafe void OpenSqlFileStream
            (
                string sPath,
                byte[] transactionContext,
                FileAccess access,
                FileOptions options,
                long allocationSize
            )
        {
            //-----------------------------------------------------------------
            // precondition validation
            // these should be checked by any caller of this method
            // ensure we have validated and normalized the path before
            Debug.Assert(sPath != null);
            Debug.Assert(transactionContext != null);

            if (access != FileAccess.Read && access != FileAccess.Write && access != FileAccess.ReadWrite)
                throw ADP.ArgumentOutOfRange("access");

            // FileOptions is a set of flags, so AND the given value against the set of values we do not support
            if ((options & ~(FileOptions.WriteThrough | FileOptions.Asynchronous | FileOptions.RandomAccess | FileOptions.SequentialScan)) != 0)
                throw ADP.ArgumentOutOfRange("options");

            //-----------------------------------------------------------------
            // normalize the provided path
            // * compress path to remove any occurrences of '.' or '..'
            // * trim whitespace from the beginning and end of the path
            // * ensure that the path starts with '\\'
            // * ensure that the path does not start with '\\.\'
            sPath = GetFullPathInternal(sPath);

            Microsoft.Win32.SafeHandles.SafeFileHandle hFile = null;
            Interop.NtDll.DesiredAccess nDesiredAccess = Interop.NtDll.DesiredAccess.FILE_READ_ATTRIBUTES | Interop.NtDll.DesiredAccess.SYNCHRONIZE;
            Interop.NtDll.CreateOptions dwCreateOptions = 0;
            Interop.NtDll.CreateDisposition dwCreateDisposition = 0;
            System.IO.FileShare nShareAccess = System.IO.FileShare.None;

            switch (access)
            {
                case System.IO.FileAccess.Read:

                    nDesiredAccess |= Interop.NtDll.DesiredAccess.FILE_READ_DATA;
                    nShareAccess = System.IO.FileShare.Delete | System.IO.FileShare.ReadWrite;
                    dwCreateDisposition = Interop.NtDll.CreateDisposition.FILE_OPEN;
                    break;

                case System.IO.FileAccess.Write:
                    nDesiredAccess |= Interop.NtDll.DesiredAccess.FILE_WRITE_DATA;
                    nShareAccess = System.IO.FileShare.Delete | System.IO.FileShare.Read;
                    dwCreateDisposition = Interop.NtDll.CreateDisposition.FILE_OVERWRITE;
                    break;

                case System.IO.FileAccess.ReadWrite:
                default:
                    // we validate the value of 'access' parameter in the beginning of this method
                    Debug.Assert(access == System.IO.FileAccess.ReadWrite);

                    nDesiredAccess |= Interop.NtDll.DesiredAccess.FILE_READ_DATA | Interop.NtDll.DesiredAccess.FILE_WRITE_DATA;
                    nShareAccess = System.IO.FileShare.Delete | System.IO.FileShare.Read;
                    dwCreateDisposition = Interop.NtDll.CreateDisposition.FILE_OVERWRITE;
                    break;
            }

            if ((options & System.IO.FileOptions.WriteThrough) != 0)
            {
                dwCreateOptions |= Interop.NtDll.CreateOptions.FILE_WRITE_THROUGH;
            }

            if ((options & System.IO.FileOptions.Asynchronous) == 0)
            {
                dwCreateOptions |= Interop.NtDll.CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT;
            }

            if ((options & System.IO.FileOptions.SequentialScan) != 0)
            {
                dwCreateOptions |= Interop.NtDll.CreateOptions.FILE_SEQUENTIAL_ONLY;
            }

            if ((options & System.IO.FileOptions.RandomAccess) != 0)
            {
                dwCreateOptions |= Interop.NtDll.CreateOptions.FILE_RANDOM_ACCESS;
            }

            try
            {
                // NOTE: the Name property is intended to reveal the publicly available moniker for the
                // FILESTREAM attributed column data. We will not surface the internal processing that
                // takes place to create the mappedPath.
                string mappedPath = InitializeNtPath(sPath);
                uint retval = 0;
                int headerSize = sizeof(Interop.NtDll.FILE_FULL_EA_INFORMATION);
                int fullSize = headerSize + transactionContext.Length + EaNameString.Length;

                byte[] buffer = ArrayPool<byte>.Shared.Rent(fullSize);

                Interop.Kernel32.SetThreadErrorMode(Interop.Kernel32.SEM_FAILCRITICALERRORS, out uint oldMode);

                try
                {
                    if (transactionContext.Length >= ushort.MaxValue)
                        throw ADP.ArgumentOutOfRange("transactionContext");

                    fixed (byte* b = buffer)
                    {
                        Interop.NtDll.FILE_FULL_EA_INFORMATION* ea = (Interop.NtDll.FILE_FULL_EA_INFORMATION*)b;
                        ea->NextEntryOffset = 0;
                        ea->Flags = 0;
                        ea->EaNameLength = (byte)(EaNameString.Length - 1); // Length does not include terminating null character.
                        ea->EaValueLength = (ushort)transactionContext.Length;

                        // We could continue to do pointer math here, chose to use Span for convenience to
                        // make sure we get the other members in the right place.
                        Span<byte> data = buffer.AsSpan(headerSize);
                        EaNameString.CopyTo(data);
                        data = data.Slice(EaNameString.Length);
                        transactionContext.AsSpan().CopyTo(data);

                        (uint status, IntPtr handle) = Interop.NtDll.CreateFile(path: mappedPath.AsSpan(),
                                                                                rootDirectory: IntPtr.Zero,
                                                                                createDisposition: dwCreateDisposition,
                                                                                desiredAccess: nDesiredAccess,
                                                                                shareAccess: nShareAccess,
                                                                                fileAttributes: 0,
                                                                                createOptions: dwCreateOptions,
                                                                                eaBuffer: b,
                                                                                eaLength: (uint)fullSize);

                        SqlClientEventSource.Log.TryAdvancedTraceEvent("SqlFileStream.OpenSqlFileStream | ADV | Object Id {0}, Desired Access 0x{1}, Allocation Size {2}, File Attributes 0, Share Access 0x{3}, Create Disposition 0x{4}, Create Options 0x{5}", ObjectID, (int)nDesiredAccess, allocationSize, (int)nShareAccess, dwCreateDisposition, dwCreateOptions);

                        retval = status;
                        hFile = new SafeFileHandle(handle, true);
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);

                    Interop.Kernel32.SetThreadErrorMode(oldMode, out oldMode);
                }

                switch (retval)
                {
                    case 0:
                        break;

                    case Interop.Errors.ERROR_SHARING_VIOLATION:
                        throw ADP.InvalidOperation(StringsHelper.GetString(Strings.SqlFileStream_FileAlreadyInTransaction));

                    case Interop.Errors.ERROR_INVALID_PARAMETER:
                        throw ADP.Argument(StringsHelper.GetString(Strings.SqlFileStream_InvalidParameter));

                    case Interop.Errors.STATUS_OBJECT_NAME_NOT_FOUND:
                    case Interop.Errors.ERROR_FILE_NOT_FOUND:
                        {
                            System.IO.DirectoryNotFoundException e = new System.IO.DirectoryNotFoundException();
                            ADP.TraceExceptionAsReturnValue(e);
                            throw e;
                        }
                    default:
                        {
                            uint error = Interop.NtDll.RtlNtStatusToDosError(retval);
                            if (error == ERROR_MR_MID_NOT_FOUND)
                            {
                                // status code could not be mapped to a Win32 error code
                                error = (uint)retval;
                            }

                            System.ComponentModel.Win32Exception e = new System.ComponentModel.Win32Exception(unchecked((int)error));
                            ADP.TraceExceptionAsReturnValue(e);
                            throw e;
                        }
                }

                if (hFile.IsInvalid)
                {
                    System.ComponentModel.Win32Exception e = new System.ComponentModel.Win32Exception(Interop.Errors.ERROR_INVALID_HANDLE);
                    ADP.TraceExceptionAsReturnValue(e);
                    throw e;
                }

                if (Interop.Kernel32.GetFileType(hFile) != Interop.Kernel32.FileTypes.FILE_TYPE_DISK)
                {
                    hFile.Dispose();
                    throw ADP.Argument(StringsHelper.GetString(StringsHelper.SqlFileStream_PathNotValidDiskResource));
                }

                // if the user is opening the SQL FileStream in read/write mode, we assume that they want to scan
                // through current data and then append new data to the end, so we need to tell SQL Server to preserve
                // the existing file contents.
                if (access == System.IO.FileAccess.ReadWrite)
                {
                    uint ioControlCode = Interop.Kernel32.CTL_CODE(FILE_DEVICE_FILE_SYSTEM,
                        IoControlCodeFunctionCode, (byte)Interop.Kernel32.IoControlTransferType.METHOD_BUFFERED,
                        (byte)Interop.Kernel32.IoControlCodeAccess.FILE_ANY_ACCESS);

                    if (!Interop.Kernel32.DeviceIoControl(hFile, ioControlCode, IntPtr.Zero, 0, IntPtr.Zero, 0, out uint cbBytesReturned, IntPtr.Zero))
                    {
                        System.ComponentModel.Win32Exception e = new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                        ADP.TraceExceptionAsReturnValue(e);
                        throw e;
                    }
                }

                // now that we've successfully opened a handle on the path and verified that it is a file,
                // use the SafeFileHandle to initialize our internal System.IO.FileStream instance
#if NETFRAMEWORK
                // NOTE: need to assert UnmanagedCode permissions for this constructor. This is relatively benign
                //   in that we've done much the same validation as in the FileStream(string path, ...) ctor case
                //   most notably, validating that the handle type corresponds to an on-disk file.
                bool bRevertAssert = false;
                try
                {
                    SecurityPermission sp = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
                    sp.Assert();
                    bRevertAssert = true;
#endif
                    System.Diagnostics.Debug.Assert(_fs == null);
                    _fs = new System.IO.FileStream(hFile, access, DefaultBufferSize, ((options & System.IO.FileOptions.Asynchronous) != 0));
#if NETFRAMEWORK
                }
                finally
                {
                    if (bRevertAssert)
                    {
                        SecurityPermission.RevertAssert();
                    }
                }
#endif
            }
            catch
            {
                if (hFile != null && !hFile.IsInvalid)
                    hFile.Dispose();

                throw;
            }
        }
        // This method exists to ensure that the requested path name is unique so that SMB/DNS is prevented
        // from collapsing a file open request to a file handle opened previously. In the SQL FILESTREAM case,
        // this would likely be a file open in another transaction, so this mechanism ensures isolation.
        static private string InitializeNtPath(string path)
        {
            // Ensure we have validated and normalized the path before
            AssertPathFormat(path);
            string uniqueId = Guid.NewGuid().ToString("N");
#if NETSTANDARD || NETFRAMEWORK
            return System.IO.PathInternal.IsDeviceUNC(path.AsSpan())
#else
            return System.IO.PathInternal.IsDeviceUNC(path)
#endif
                ? string.Format(CultureInfo.InvariantCulture, @"{0}\{1}", path.Replace(@"\\.", @"\??"), uniqueId)
                : string.Format(CultureInfo.InvariantCulture, @"\??\UNC\{0}\{1}", path.Trim('\\'), uniqueId);
        }
    }
}