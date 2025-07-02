// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Reflection;
using System.Threading;
using Microsoft.Data.SqlClient.ManualTesting.Tests.SystemDataInternals;

namespace Microsoft.Data.SqlClient.ManualTesting.Tests
{
#if NETFRAMEWORK
    internal static class DictionaryExtensions
    {
        public static bool TryAdd<TKey, TValue>(this IDictionary<TKey, TValue> dict, TKey key, TValue value)
        {
            if (!dict.ContainsKey(key))
            {
                dict.Add(key, value);
                return true;
            }

            return false;
        }
    }
#endif

    public class InternalConnectionWrapper
    {
        private static Dictionary<string, string> s_killByTSqlConnectionStrings = new Dictionary<string, string>();
        private static ReaderWriterLockSlim s_killByTSqlConnectionStringsLock = new ReaderWriterLockSlim();

        private object _internalConnection = null;
        private object _spid = null;

        /// <summary>
        /// Is this internal connection enlisted in a distributed transaction?
        /// </summary>
        public bool IsEnlistedInTransaction => ConnectionHelper.IsEnlistedInTransaction(_internalConnection);

        /// <summary>
        /// Is this internal connection the root of a distributed transaction?
        /// </summary>
        public bool IsTransactionRoot => ConnectionHelper.IsTransactionRoot(_internalConnection);

        /// <summary>
        /// True if this connection is the root of a transaction AND it is waiting for the transaction 
        /// to complete (i.e. it has been 'aged' or 'put into stasis'), otherwise false
        /// </summary>
        public bool IsTxRootWaitingForTxEnd => ConnectionHelper.IsTxRootWaitingForTxEnd(_internalConnection);

        /// <summary>
        /// Gets the internal connection associated with the given SqlConnection
        /// </summary>
        /// <param name="connection">Live outer connection to grab the inner connection from</param>
        /// <param name="supportKillByTSql">If true then we will query the server for this connection's SPID details (to be used in the KillConnectionByTSql method)</param>
        public InternalConnectionWrapper(SqlConnection connection, bool supportKillByTSql = false, string originalConnectionString = "")
        {
            if (connection == null)
                throw new ArgumentNullException(nameof(connection));

            _internalConnection = connection.GetInternalConnection();
            ConnectionString = connection.ConnectionString;

            if (supportKillByTSql)
            {
                SqlConnectionStringBuilder csb = new SqlConnectionStringBuilder(ConnectionString);
                if (!csb.IntegratedSecurity &&
                    string.IsNullOrWhiteSpace(originalConnectionString))
                {
                    throw new ArgumentException("Must provide originalConnectionString if using supportKillByTSql and not using Integrated Security.");
                }
                else if (!string.IsNullOrWhiteSpace(originalConnectionString))
                {
                    ConnectionString = originalConnectionString;
                }

                // Save the SPID for later use
                using (SqlCommand command = new SqlCommand("SELECT @@SPID", connection))
                {
                    _spid = command.ExecuteScalar();
                }
            }
        }

        /// <summary>
        /// Gets the connection pool this internal connection is in
        /// </summary>
        public ConnectionPoolWrapper ConnectionPool
        { get { return new ConnectionPoolWrapper(_internalConnection, ConnectionString); } }

        /// <summary>
        /// Is this internal connection associated with the given SqlConnection
        /// </summary>
        /// <param name="connection"></param>
        /// <returns></returns>
        public bool IsInternalConnectionOf(SqlConnection connection)
        {
            if (connection == null)
                throw new ArgumentNullException(nameof(connection));

            return (_internalConnection == connection.GetInternalConnection());
        }


        /// <summary>
        /// The connection string used to create this connection
        /// </summary>
        public string ConnectionString { get; private set; }

        /// <summary>
        /// True if the connection is still alive, otherwise false
        /// NOTE: Do NOT use this on a connection that is currently in use (There is a Debug.Assert and it will always return true)
        /// NOTE: If the connection is dead, it will be marked as 'broken'
        /// </summary>
        public bool IsConnectionAlive()
        {
            return ConnectionHelper.IsConnectionAlive(_internalConnection);
        }

        /// <summary>
        /// Will attempt to kill the connection
        /// </summary>
        public void KillConnection()
        {
            object tdsParser = ConnectionHelper.GetParser(_internalConnection);
            object stateObject = TdsParserHelper.GetStateObject(tdsParser);

            Assembly assembly = Assembly.Load(new AssemblyName(typeof(SqlConnection).GetTypeInfo().Assembly.FullName));
            Type sniHandleType = assembly.GetType("Microsoft.Data.SqlClient.ManagedSni.SniHandle");

            MethodInfo killConn = null;
            if (sniHandleType is not null)
            {
                killConn = sniHandleType.GetMethod("KillConnection");
            }
            
            if (killConn is null)
            {
                throw new InvalidOperationException("Error: Could not find SNI KillConnection test hook. This operation is only supported in debug builds.");
            }
                
            killConn.Invoke(
                TdsParserStateObjectHelper.GetSessionHandle(stateObject),
                null);

            // Ensure kill occurs outside of check connection window
            Thread.Sleep(100);
        }

        /// <summary>
        /// Requests that the server kills this connection
        /// NOTE: InternalConnectionWrapper must be created with SupportKillByTSql enabled
        /// </summary>
        public void KillConnectionByTSql()
        {
            if (_spid != null)
            {
                using (SqlConnection connection = new SqlConnection(GetKillByTSqlConnectionString()))
                {
                    connection.Open();
                    using (SqlCommand command = new SqlCommand(string.Format("KILL {0}", _spid), connection))
                    {
                        command.ExecuteNonQuery();
                    }
                }
                // Ensure kill occurs outside of check connection window
                Thread.Sleep(100);
            }
            else
            {
                throw new InvalidOperationException("Kill by TSql not enabled on this InternalConnectionWrapper");
            }
        }

        /// <summary>
        /// Gets a connection string that can be used to send a command to the server to kill this connection
        /// </summary>
        /// <returns>A connection string</returns>
        private string GetKillByTSqlConnectionString()
        {
            string killConnectionString = null;
            bool containsConnectionString = true;

            try
            {
                s_killByTSqlConnectionStringsLock.EnterReadLock();
                containsConnectionString = s_killByTSqlConnectionStrings.TryGetValue(ConnectionString, out killConnectionString);
            }
            finally
            {
                s_killByTSqlConnectionStringsLock.ExitReadLock();
            }
            if (!containsConnectionString)
            {
                killConnectionString = CreateKillByTSqlConnectionString(ConnectionString);

                try
                {
                    s_killByTSqlConnectionStringsLock.EnterWriteLock();
                    s_killByTSqlConnectionStrings.TryAdd(ConnectionString, killConnectionString);
                }
                finally
                {
                    s_killByTSqlConnectionStringsLock.ExitWriteLock();
                }
            }

            return killConnectionString;
        }

        /// <summary>
        /// Converts a connection string for a format which is appropriate to kill another connection with (i.e. non-pooled, no transactions)
        /// </summary>
        /// <param name="connectionString">Base connection string to convert</param>
        /// <returns>The converted connection string</returns>
        private static string CreateKillByTSqlConnectionString(string connectionString)
        {
            SqlConnectionStringBuilder builder = new SqlConnectionStringBuilder(connectionString);
            // Avoid tampering with the connection pool
            builder.Pooling = false;
            return builder.ConnectionString;
        }

        // override object.Equals
        public override bool Equals(object obj)
        {
            bool areEquals = false;

            InternalConnectionWrapper objAsWrapper = obj as InternalConnectionWrapper;
            if ((objAsWrapper != null) && (objAsWrapper._internalConnection == _internalConnection))
                areEquals = true;

            return areEquals;
        }

        // override object.GetHashCode
        public override int GetHashCode()
        {
            return _internalConnection.GetHashCode();
        }
    }
}
