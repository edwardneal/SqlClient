// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Data;
using System.Text;
using Microsoft.Data.SqlClient.ManualTesting.Tests;
using Microsoft.Data.SqlClient.Tests.Common.Fixtures.DatabaseObjects;
using Xunit;

namespace Microsoft.Data.SqlClient.ManualTests.BulkCopy
{
    internal enum ColumnsEnum
    {
        _int = 0,
        _varChar3 = 1
    }

    [Trait("Set", "2")]
    public class DataConversionErrorMessageTest
    {
        private enum SourceType
        {
            DataTable,
            DataRows,
            DataReader
        }

        // Synapse: Column count in target table does not match column count specified in input.
        //          If BCP command, ensure format file column count matches destination table.
        //          If SSIS data import, check column mappings are consistent with target.
        [ConditionalFact(typeof(DataTestUtility), nameof(DataTestUtility.AreConnStringsSetup), nameof(DataTestUtility.IsNotAzureSynapse))]
        public void StringToIntErrorMessageTest()
        {
            using SqlConnection dstConn = new(DataTestUtility.TCPConnectionString);
            using Table dstTable = new(dstConn, nameof(StringToIntErrorMessageTest), @$"(
    {nameof(ColumnsEnum._int)} int NULL,
    {nameof(ColumnsEnum._varChar3)} varchar(3) NULL
)");

            Assert.True(StringToIntTest(dstConn, dstTable.Name, SourceType.DataTable), "Did not get any exceptions for DataTable when converting data from 'string' to 'int' datatype!");
            Assert.True(StringToIntTest(dstConn, dstTable.Name, SourceType.DataRows), "Did not get any exceptions for DataRow[] when converting data from 'string' to 'int' datatype!");
            Assert.True(StringToIntTest(dstConn, dstTable.Name, SourceType.DataReader), "Did not get any exceptions for DataReader when converting data from 'string' to 'int' datatype!");
        }

        private bool StringToIntTest(SqlConnection cnn, string targetTable, SourceType sourceType)
        {
            var value = "abcde";
            int rowNo = -1;

            DataTable table = PrepareDataTable(targetTable, ColumnsEnum._varChar3, value);

            bool hitException = false;
            try
            {
                using (SqlBulkCopy bulkcopy = new SqlBulkCopy(cnn))
                {
                    bulkcopy.DestinationTableName = targetTable;
                    bulkcopy.ColumnMappings.Add(new SqlBulkCopyColumnMapping((int)ColumnsEnum._varChar3, (int)ColumnsEnum._int));
                    switch (sourceType)
                    {
                        case SourceType.DataTable:
                            rowNo = table.Rows.Count;
                            bulkcopy.WriteToServer(table);
                            break;
                        case SourceType.DataRows:
                            rowNo = table.Rows.Count;
                            bulkcopy.WriteToServer(table.Select());
                            break;
                        case SourceType.DataReader:
                            bulkcopy.WriteToServer(table.CreateDataReader());
                            break;
                        default:
                            break;
                    }

                    bulkcopy.Close();
                }
            }
            catch (Exception ex)
            {
                string pattern;
                object[] args = new object[] { string.Format(" '{0}'", value), value.GetType().Name, "int", (int)ColumnsEnum._int, Enum.GetName(typeof(ColumnsEnum), ColumnsEnum._int), rowNo };
                if (rowNo == -1)
                {
                    Array.Resize(ref args, args.Length - 1);
                    pattern = SystemDataResourceManager.Instance.SQL_BulkLoadCannotConvertValueWithoutRowNo;
                }
                else
                {
                    pattern = SystemDataResourceManager.Instance.SQL_BulkLoadCannotConvertValue;
                }

                string expectedErrorMsg = string.Format(pattern, args);

                Assert.True(ex.Message.Contains(expectedErrorMsg), "Unexpected error message: " + ex.Message);
                hitException = true;
            }
            return hitException;
        }

        private DataTable PrepareDataTable(string tableName, ColumnsEnum selectedColumn, object value)
        {
            var table = new DataTable(tableName);

            table.Columns.Add(Enum.GetName(typeof(ColumnsEnum), ColumnsEnum._int), typeof(int));
            table.Columns.Add(Enum.GetName(typeof(ColumnsEnum), ColumnsEnum._varChar3), typeof(string));

            var row = table.NewRow();
            row[(int)selectedColumn] = value;

            table.Rows.Add(row);

            return table;
        }
    }
}
