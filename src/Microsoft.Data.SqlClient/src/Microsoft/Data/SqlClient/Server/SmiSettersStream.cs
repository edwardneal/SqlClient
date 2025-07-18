// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using Microsoft.Data.Common;

namespace Microsoft.Data.SqlClient.Server
{
    internal class SmiSettersStream : Stream
    {
        private ITypedSettersV3 _setters;
        private int _ordinal;
        private long _lengthWritten;
        private SmiMetaData _metaData;

        internal SmiSettersStream(ITypedSettersV3 setters, int ordinal, SmiMetaData metaData)
        {
            Debug.Assert(setters != null);
            Debug.Assert(0 <= ordinal);
            Debug.Assert(metaData != null);

            _setters = setters;
            _ordinal = ordinal;
            _lengthWritten = 0;
            _metaData = metaData;
        }

        public override bool CanRead
        {
            get
            {
                return false;
            }
        }

        // If CanSeek is false, Position, Seek, Length, and SetLength should throw.
        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        public override bool CanWrite
        {
            get
            {
                return true;
            }
        }

        public override long Length
        {
            get
            {
                return _lengthWritten;
            }
        }

        public override long Position
        {
            get
            {
                return _lengthWritten;
            }
            set
            {
                throw SQL.StreamSeekNotSupported();
            }
        }

        public override void Flush()
        {
            _lengthWritten = ValueUtilsSmi.SetBytesLength(_setters, _ordinal, _metaData, _lengthWritten);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw SQL.StreamSeekNotSupported();
        }

        public override void SetLength(long value)
        {
            if (value < 0)
            {
                throw ADP.ArgumentOutOfRange(nameof(value));
            }
            ValueUtilsSmi.SetBytesLength(_setters, _ordinal, _metaData, value);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw SQL.StreamReadNotSupported();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _lengthWritten += ValueUtilsSmi.SetBytes(_setters, _ordinal, _metaData, _lengthWritten, buffer, offset, count);
        }
    }
}
