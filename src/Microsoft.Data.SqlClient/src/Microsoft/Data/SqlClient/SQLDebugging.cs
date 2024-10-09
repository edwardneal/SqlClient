// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System;

namespace Microsoft.Data.SqlClient
{
    //
    // This is a private interface for the SQL Debugger
    // You must not change the guid for this coclass
    // or the iid for the ISQLDebug interface
    //
    /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlDebugging.xml' path='docs/members[@name="SQLDebugging"]/SQLDebugging/*'/>
    [ComVisible(true)]
    [ClassInterface(ClassInterfaceType.None)]
    [Guid("afef65ad-4577-447a-a148-83acadd3d4b9")]
    [EditorBrowsable(EditorBrowsableState.Never)]
    [Obsolete("Microsoft.Data.SqlClient does not support debugging SQL Server 2000 connections.")]
#if NETFRAMEWORK
    [System.Security.Permissions.PermissionSetAttribute(System.Security.Permissions.SecurityAction.LinkDemand, Name = "FullTrust")]
#endif
    public sealed class SQLDebugging : SQLDebugging.ISQLDebug
    {
        // this is a private interface to com+ users
        // do not change this guid
        [ComImport]
        [ComVisible(true)]
        [Guid("6cb925bf-c3c0-45b3-9f44-5dd67c7b7fe8")]
        [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        [BestFitMapping(false, ThrowOnUnmappableChar = true)]
        interface ISQLDebug
        {

#if NETFRAMEWORK
            [System.Security.Permissions.PermissionSetAttribute(System.Security.Permissions.SecurityAction.LinkDemand, Name = "FullTrust")]
#endif
            bool SQLDebug(int dwpidDebugger, int dwpidDebuggee, [MarshalAs(UnmanagedType.LPStr)] string pszMachineName,
                [MarshalAs(UnmanagedType.LPStr)] string pszSDIDLLName, int dwOption, int cbData, byte[] rgbData);
        }

        /// <include file='../../../../doc/snippets/Microsoft.Data.SqlClient/SQLDebugging.xml' path='docs/members[@name="SQLDebugging"]/ctor/*'/>
        [Obsolete("Microsoft.Data.SqlClient does not support debugging SQL Server 2000 connections.")]
        public SQLDebugging()
        {
            throw new NotSupportedException();
        }

        [ResourceExposure(ResourceScope.None)]
        [ResourceConsumption(ResourceScope.Machine, ResourceScope.Machine)]
        bool ISQLDebug.SQLDebug(int dwpidDebugger, int dwpidDebuggee, [MarshalAs(UnmanagedType.LPStr)] string pszMachineName,
            [MarshalAs(UnmanagedType.LPStr)] string pszSDIDLLName, int dwOption, int cbData, byte[] rgbData)
        {
            throw new NotSupportedException();
        }
    }
}
