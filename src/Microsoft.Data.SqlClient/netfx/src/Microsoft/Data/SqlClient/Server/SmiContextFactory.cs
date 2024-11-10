// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;

namespace Microsoft.Data.SqlClient.Server
{

    sealed internal class SmiContextFactory
    {
        public static readonly SmiContextFactory Instance = new SmiContextFactory();

        internal const ulong Sql2005Version = 100;
        internal const ulong Sql2008Version = 210;
        internal const ulong LatestVersion = Sql2008Version;

        // Used as the key for SmiContext.GetContextValue()
        internal enum ContextKey
        {
            Connection = 0,
            SqlContext = 1
        }


        private SmiContextFactory()
        {
        }

        internal ulong NegotiatedSmiVersion
        {
            get
            {
                throw SQL.ContextUnavailableOutOfProc();    // Must not be a valid version of Sql Server, or not be SqlCLR
            }
        }

        internal string ServerVersion
        {
            get
            {
                throw SQL.ContextUnavailableOutOfProc();    // Must not be a valid version of Sql Server, or not be SqlCLR
            }
        }
    }
}

