// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Data.Common;
using Microsoft.SqlServer.Server;

namespace Microsoft.Data.SqlClient.Server
{
    internal static class SerializationHelperSql9
    {
        // Get the m_size of the serialized stream for this type, in bytes.
        // This method creates an instance of the type using the public
        // no-argument constructor, serializes it, and returns the m_size
        // in bytes.
        // Prevent inlining so that reflection calls are not moved to caller that may be in a different assembly that may have a different grant set.
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static int SizeInBytes(
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
#endif
            Type t) => SizeInBytes(Activator.CreateInstance(t));

        // Get the m_size of the serialized stream for this type, in bytes.
        internal static int SizeInBytes(object instance)
        {
            DummyStream stream = new DummyStream();
            Serializer ser = GetSerializer(instance.GetType());
            ser.Serialize(stream, instance);
            return (int)stream.Length;
        }

        internal static void Serialize(Stream s, object instance)
        {
            GetSerializer(instance.GetType()).Serialize(s, instance);
        }

        internal static object Deserialize(Stream s,
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
#endif
            Type resultType) => GetSerializer(resultType).Deserialize(s);


        // Cache the relationship between a type and its serializer.
        // This is expensive to compute since it involves traversing the
        // custom attributes of the type using reflection.
        private static ConcurrentDictionary<Type, Serializer> s_types2Serializers;

        private static Serializer GetSerializer(
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
#endif
            Type t)
        {
            if (s_types2Serializers == null)
            {
                s_types2Serializers = new ConcurrentDictionary<Type, Serializer>();
            }

            Serializer s;
            if (!s_types2Serializers.TryGetValue(t, out s))
            {
                s = GetNewSerializer(t);
                s_types2Serializers[t] = s;
            }

            return s;
        }

        internal static int GetUdtMaxLength(
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
#endif
            Type t)
        {
            SqlUdtInfo udtInfo = SqlUdtInfo.GetFromType(t);

            if (Format.Native == udtInfo.SerializationFormat)
            {
                // In the native format, the user does not specify the
                // max byte size, it is computed from the type definition
                return SizeInBytes(t);
            }
            else
            {
                // In all other formats, the user specifies the maximum size in bytes.
                return udtInfo.MaxByteSize;
            }
        }

        private static object[] GetCustomAttributes(Type t)
            => t.GetCustomAttributes(typeof(SqlUserDefinedTypeAttribute), false);

        internal static SqlUserDefinedTypeAttribute GetUdtAttribute(Type t)
        {
            SqlUserDefinedTypeAttribute udtAttr;
            object[] attr = GetCustomAttributes(t);
            if (attr != null && attr.Length == 1)
            {
                udtAttr = (SqlUserDefinedTypeAttribute)attr[0];
            }
            else
            {
                throw ADP.CreateInvalidUdtException(t, nameof(Strings.SqlUdtReason_NoUdtAttribute));
            }
            return udtAttr;
        }

        // Create a new serializer for the given type.
        private static Serializer GetNewSerializer(
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
#endif
            Type t)
        {
            SqlUserDefinedTypeAttribute udtAttr = GetUdtAttribute(t);
          
            switch (udtAttr.Format)
            {
                case Format.Native:
                    return new NormalizedSerializer(t);
                case Format.UserDefined:
                    return new BinarySerializeSerializer(t);
                case Format.Unknown: // should never happen, but fall through
                default:
                    throw ADP.InvalidUserDefinedTypeSerializationFormat(udtAttr.Format);
            }
        }
    }

    // The base serializer class.
    internal abstract class Serializer
    {
#if NET
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
#endif
        protected Type _type;

        public abstract object Deserialize(Stream s);
        public abstract void Serialize(Stream s, object o);

        protected Serializer(
#if NET
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
#endif
            Type t) => _type = t;
    }

    internal sealed class NormalizedSerializer : Serializer
    {
        private readonly BinaryOrderedUdtNormalizer _normalizer;
   
        internal NormalizedSerializer(
#if NET
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicProperties)]
#endif
            Type t) : base(t)
        {
            _normalizer = new BinaryOrderedUdtNormalizer(t);
        }

        public override void Serialize(Stream s, object o) => _normalizer.NormalizeTopObject(o, s);

        public override object Deserialize(Stream s) => _normalizer.DeNormalizeTopObject(_type, s);
    }

    internal sealed class BinarySerializeSerializer : Serializer
    {
        internal BinarySerializeSerializer(
#if NET
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
#endif
            Type t) : base(t)
        {
        }

        public override void Serialize(Stream s, object o)
        {
            BinaryWriter w = new BinaryWriter(s);
            ((IBinarySerialize)o).Write(w);
        }

        // Prevent inlining so that reflection calls are not moved
        // to a caller that may be in a different assembly that may
        // have a different grant set.
        [MethodImpl(MethodImplOptions.NoInlining)]
        public override object Deserialize(Stream s)
        {
            object instance = Activator.CreateInstance(_type);
            BinaryReader r = new BinaryReader(s);
           ((IBinarySerialize)instance).Read(r);
            return instance;
        }
    }

    // A dummy stream class, used to get the number of bytes written
    // to the stream.
    internal sealed class DummyStream : Stream
    {
        private long _size;

        public DummyStream()
        {
        }

        private void DontDoIt()
        {
            throw new Exception(StringsHelper.GetString(Strings.Sql_InternalError));
        }

        public override bool CanRead => false;

        public override bool CanWrite => true;

        public override bool CanSeek => false;

        public override long Position
        {
            get => _size;
            set => _size = value;
        }

        public override long Length => _size;

        public override void SetLength(long value) => _size = value;

        public override long Seek(long value, SeekOrigin loc)
        {
            DontDoIt();
            return -1;
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            DontDoIt();
            return -1;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            _size += count;
        }
    }
}
