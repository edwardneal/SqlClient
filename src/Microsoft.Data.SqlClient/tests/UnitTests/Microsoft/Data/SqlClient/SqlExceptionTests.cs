// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using Xunit;

namespace Microsoft.Data.SqlClient.UnitTests;

public class SqlExceptionTests
{
    [Fact]
    public void Serialization_RoundTrips_Properties()
    {
        SqlError originalError = new(
                infoNumber: 123,
                errorState: 0x02,
                errorClass: 0x03,
                server: "foo",
                errorMessage: "bar",
                procedure: "baz",
                lineNumber: 234,
                exception: new Exception(),
                batchIndex: 345);
        SqlErrorCollection errorCollection = [originalError];
        SqlBatchCommand batchCommand = new();
        SqlException originalException = SqlException.CreateException(errorCollection, "version", Guid.NewGuid(), originalError.Exception, batchCommand);

        originalException.HelpLink = nameof(originalException.HelpLink);
        originalException._doNotReconnect = true;

        // Use DataContractSerializer to serialize and deserialize the exception with a list of
        // known types. This is necessary because the base Exception class' Data property is of
        // a non-public type (System.Collections.ListDictionaryInternal) which is not directly
        // serializable, and the serializer needs to know about it in advance to handle it properly.
        DataContractSerializer serializer = new(typeof(SqlException),
            [originalError.Exception.GetType(), errorCollection.GetType(), originalError.GetType(), originalException.Data.GetType()]);
        using MemoryStream stream = new();

        serializer.WriteObject(stream, originalException);
        stream.Position = 0;

        SqlException? deserializedException = serializer.ReadObject(stream) as SqlException;

        // The original inner exception will be non-null.
        Assert.NotNull(originalException.InnerException);

        // The exception should deserialize successfully and all properties and fields besides
        // _doNotReconnect and BatchCommand should match the original values.
        Assert.NotNull(deserializedException);
        Assert.Equal(originalException.ClientConnectionId, deserializedException.ClientConnectionId);
        Assert.Equal(originalException.Class, deserializedException.Class);
        Assert.Equal(originalException.LineNumber, deserializedException.LineNumber);
        Assert.Equal(originalException.Number, deserializedException.Number);
        Assert.Equal(originalException.Procedure, deserializedException.Procedure);
        Assert.Equal(originalException.Server, deserializedException.Server);
        Assert.Equal(originalException.State, deserializedException.State);
        Assert.Equal(originalException.Source, deserializedException.Source);
        Assert.Equal(originalException.HelpLink, deserializedException.HelpLink);

        Assert.NotNull(deserializedException.InnerException);
        Assert.Equal(originalException.InnerException.Message, deserializedException.InnerException.Message);
        Assert.Equal(originalException.InnerException.HResult, deserializedException.InnerException.HResult);

        // Verify the data dictionary was serialized and deserialized, including the additional
        // "SqlError 1" entry added by GetObjectData.
        Assert.NotEmpty(deserializedException.Data);
        Assert.Contains("HelpLink.ProdName", deserializedException.Data.Keys.Cast<string>());
        Assert.Contains("HelpLink.ProdVer", deserializedException.Data.Keys.Cast<string>());
        Assert.Contains("HelpLink.EvtSrc", deserializedException.Data.Keys.Cast<string>());
        Assert.Contains("HelpLink.EvtID", deserializedException.Data.Keys.Cast<string>());
        Assert.Contains("HelpLink.BaseHelpUrl", deserializedException.Data.Keys.Cast<string>());
        Assert.Contains("HelpLink.LinkId", deserializedException.Data.Keys.Cast<string>());

        Assert.Contains("SqlError 1", deserializedException.Data.Keys.Cast<string>());
        string deserializedSqlErrorData = Assert.IsType<string>(deserializedException.Data["SqlError 1"]);
        Assert.Equal(originalError.ToString(), deserializedSqlErrorData);

        // Several top-level fields are explicitly not serialized, and should not match
        // following deserialization.
        Assert.True(originalException._doNotReconnect);
        Assert.False(deserializedException._doNotReconnect);

        Assert.NotNull(originalException.BatchCommand);
        Assert.Null(deserializedException.BatchCommand);

        // Proceed to verifying the properties of the contained SqlError, which should all match
        // following deserialization.
        Assert.NotNull(deserializedException.Errors);
        Assert.NotEmpty(deserializedException.Errors);

        SqlError? deserializedError = (SqlError?)Assert.Single(deserializedException.Errors);

        Assert.NotNull(deserializedError);
        Assert.Equal(originalError.Source, deserializedError.Source);
        Assert.Equal(originalError.Number, deserializedError.Number);
        Assert.Equal(originalError.State, deserializedError.State);
        Assert.Equal(originalError.Class, deserializedError.Class);
        Assert.Equal(originalError.Server, deserializedError.Server);
        Assert.Equal(originalError.Message, deserializedError.Message);
        Assert.Equal(originalError.Procedure, deserializedError.Procedure);
        Assert.Equal(originalError.LineNumber, deserializedError.LineNumber);
        Assert.Equal(originalError.Win32ErrorCode, deserializedError.Win32ErrorCode);
        Assert.Equal(originalError.BatchIndex, deserializedError.BatchIndex);

        Assert.NotNull(originalError.Exception);
        Assert.Equal(originalError.Exception.Message, deserializedError.Exception.Message);
        Assert.Equal(originalError.Exception.HResult, deserializedError.Exception.HResult);
    }
}
