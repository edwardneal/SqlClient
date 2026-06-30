// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.Reflection;
using System.Text;
using Microsoft.Data.SqlClient.Tests.Common.Fixtures.DatabaseObjects;
using Xunit;

namespace Microsoft.Data.SqlClient.ManualTesting.Tests
{
    [Trait("Set", "3")]
    public class SqlCommandSetTest
    {
        private static Assembly mds = Assembly.GetAssembly(typeof(SqlConnection));

        // Synapse: The statement failed. Column 'ByteArrayColumn' has a data type that cannot participate in a columnstore index.
        [ConditionalFact(typeof(DataTestUtility), nameof(DataTestUtility.AreConnStringsSetup), nameof(DataTestUtility.IsNotAzureSynapse))]
        public void TestByteArrayParameters()
        {
            byte[] bArray = new byte[] { 1, 2, 3 };

            using (var connection = new SqlConnection(DataTestUtility.TCPConnectionString))
            using (var cmd = connection.CreateCommand())
            {
                using (Table byteArrayTable = new(connection, nameof(TestByteArrayParameters), "(ByteArrayColumn varbinary(max))"))
                using (StoredProcedure byteArrayProc = new(connection, nameof(TestByteArrayParameters), $"@array varbinary(max) AS BEGIN SET NOCOUNT ON; " +
                    $"insert into {byteArrayTable.Name}(ByteArrayColumn) values(@array) END"))
                {

                    // Insert with SqlCommand
                    cmd.CommandText = byteArrayProc.Name;
                    cmd.CommandType = System.Data.CommandType.StoredProcedure;
                    SqlCommandBuilder.DeriveParameters(cmd);
                    cmd.Parameters["@array"].Value = bArray;

                    cmd.ExecuteNonQuery();

                    //Insert with command Set
                    var commandSetType = mds.GetType("Microsoft.Data.SqlClient.SqlCommandSet");
                    var cmdSet = Activator.CreateInstance(commandSetType, true);
                    commandSetType.GetMethod("Append", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).Invoke(cmdSet, new object[] { cmd });
                    commandSetType.GetProperty("Connection", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).GetSetMethod(true).Invoke(cmdSet, new object[] { connection });
                    commandSetType.GetMethod("ExecuteNonQuery", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance).Invoke(cmdSet, new object[] { });

                    cmd.CommandType = System.Data.CommandType.Text;
                    cmd.CommandText = $"SELECT * FROM {byteArrayTable.Name}";
                    using (SqlDataReader reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            SqlBytes byteArray = reader.GetSqlBytes(0);
                            Assert.Equal(byteArray.Length, bArray.Length);

                            for (int i = 0; i < bArray.Length; i++)
                            {
                                Assert.Equal(bArray[i], byteArray[i]);
                            }
                        }
                    }
                }
            }
        }
    }
}
