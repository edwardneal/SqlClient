﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Data.SqlClient.Server;
using Microsoft.Data.SqlClient.UnitTests.UdtSerialization.SerializedTypes;
using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace Microsoft.Data.SqlClient.UnitTests.UdtSerialization;

/// <summary>
/// Tests the user-defined UDT serialization method. Verifies that custom types round-trip.
/// </summary>
public sealed class UserDefinedSerializationTest : IDisposable
{
    private readonly MemoryStream _stream;

    /// <summary>
    /// Initializes the MemoryStream used for all tests in this class.
    /// </summary>
    public UserDefinedSerializationTest()
    {
        _stream = new MemoryStream();
    }

    void IDisposable.Dispose()
    {
        _stream.Dispose();
    }

    /// <summary>
    /// Attempts to serialize and deserialize an instance of a struct with a user-defined serialization method.
    /// </summary>
    /// <seealso cref="Serialize_Class_Roundtrips"/>
    [Fact]
    public void Serialize_Struct_Roundtrips() =>
        RoundtripType(new UserDefinedFormattedStruct((IntPtr)0x12345678));

    /// <summary>
    /// Attempts to serialize and deserialize an instance of a class with a user-defined serialization method.
    /// </summary>
    /// <seealso cref="Serialize_Struct_Roundtrips"/>
    [Fact]
    public void Serialize_Class_Roundtrips() =>
        RoundtripType(new UserDefinedFormattedClass((IntPtr)0x12345678));

    /// <summary>
    /// Attempts to deserialize an instance of a type with a user-defined serialization method but without a public
    /// parameterless constructor. Verifies that this fails.
    /// </summary>
    [Fact]
    public void Deserialize_MissingPublicParameterlessConstructor_Throws()
    {
        SerializationHelperSql9.Serialize(_stream, new UserDefinedMissingPublicConstructor(true));
        _stream.Seek(0, SeekOrigin.Begin);

        Action deserialize = () => SerializationHelperSql9.Deserialize(_stream, typeof(UserDefinedMissingPublicConstructor));

        Assert.Throws<MissingMethodException>(deserialize);
    }

    /// <summary>
    /// Attempts to deserialize an instance of a type with a user-defined serialization method but which does not,
    /// implement IBinarySerialize. Verifies that this fails.
    /// </summary>
    [Fact]
    public void Serialize_DoesNotImplementIBinarySerialize_Throws()
    {
        Action serialize = () => SerializationHelperSql9.Serialize(_stream, new UserDefinedDoesNotImplementIBinarySerialize());

        Assert.Throws<InvalidCastException>(serialize);
    }

    private void RoundtripType<T>(T userObject)
        where T : IFormattingProgress
    {
        int typeSize = SerializationHelperSql9.SizeInBytes(userObject.GetType());
        int objectSize = SerializationHelperSql9.SizeInBytes(userObject);
        int maxTypeSize = SerializationHelperSql9.GetUdtMaxLength(userObject.GetType());

        SerializationHelperSql9.Serialize(_stream, userObject);
        _stream.Seek(0, SeekOrigin.Begin);
        byte[] serializedValue = _stream.ToArray();
        T readInstance = (T)SerializationHelperSql9.Deserialize(_stream, userObject.GetType());

        // If this is a struct, it will have been copied by value and the write to WriteInvoked will have been made
        // to another copy of our object
        if (!typeof(T).IsValueType)
        {
            Assert.True(userObject.WriteInvoked);
        }

        Assert.Equal(IntPtr.Size, typeSize);
        Assert.Equal(IntPtr.Size, objectSize);
        Assert.Equal(11, maxTypeSize);

        Assert.Equal(IntPtr.Size, serializedValue.Length);
        if (IntPtr.Size == 8)
        {
            Assert.Equal([0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00], serializedValue);
        }
        else if (IntPtr.Size == 4)
        {
            Assert.Equal([0x78, 0x56, 0x34, 0x12], serializedValue);
        }
        else
        {
            Assert.Fail("Invalid IntPtr size.");
        }

        // In .NET Framework, Activator.CreateInstance does not invoke a struct's parameterless constructor
#if NET
        Assert.NotEqual(userObject.ParameterlessConstructorInvoked, readInstance.ParameterlessConstructorInvoked);
        Assert.True(readInstance.ParameterlessConstructorInvoked);
#endif
        Assert.True(readInstance.ReadInvoked);

        Assert.Equal(userObject, readInstance);
    }
}
