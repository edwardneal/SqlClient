﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Data;
using System.Data.Common;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.SqlServer.TDS;
using Microsoft.SqlServer.TDS.FeatureExtAck;
using Microsoft.SqlServer.TDS.Login7;
using Microsoft.SqlServer.TDS.PreLogin;
using Microsoft.SqlServer.TDS.Servers;
using Xunit;

namespace Microsoft.Data.SqlClient.UnitTests.SimulatedServerTests
{
    public class ConnectionTests
    {
        [Fact]
        public void ConnectionTest()
        {
            using TdsServer server = new(new TdsServerArguments() { });
            server.Start();
            var connStr = new SqlConnectionStringBuilder() {
                DataSource = $"localhost,{server.EndPoint.Port}",
                Encrypt = SqlConnectionEncryptOption.Optional,
            }.ConnectionString;
            using SqlConnection connection = new(connStr);
            connection.Open();
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Windows)]
        public void IntegratedAuthConnectionTest()
        {
            using TdsServer server = new(new TdsServerArguments() { });
            server.Start();
            var connStr = new SqlConnectionStringBuilder() {
                DataSource = $"localhost,{server.EndPoint.Port}",
                Encrypt = SqlConnectionEncryptOption.Optional,
            }.ConnectionString;
            SqlConnectionStringBuilder builder = new(connStr);
            builder.IntegratedSecurity = true;
            using SqlConnection connection = new(builder.ConnectionString);
            connection.Open();
        }

        /// <summary>
        /// Runs a test where TDS Server doesn't send encryption info during pre-login response.
        /// The driver is expected to fail when that happens, and terminate the connection during pre-login phase 
        /// when client enables encryption using Encrypt=true or uses default encryption setting.
        /// </summary>
        [Fact]
        public async Task RequestEncryption_ServerDoesNotSupportEncryption_ShouldFail()
        {
            using TdsServer server = new(new TdsServerArguments() {Encryption = TDSPreLoginTokenEncryptionType.None });
            server.Start();
            var connStr = new SqlConnectionStringBuilder() {
                DataSource = $"localhost,{server.EndPoint.Port}"
            }.ConnectionString;

            using SqlConnection connection = new(connStr);
            Exception ex = await Assert.ThrowsAsync<SqlException>(async () => await connection.OpenAsync());
            Assert.Contains("The instance of SQL Server you attempted to connect to does not support encryption.", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(40613)]
        [InlineData(42108)]
        [InlineData(42109)]
        public async Task TransientFault_RetryEnabled_ShouldSucceed_Async(uint errorCode)
        {
            using TransientTdsErrorTdsServer server = new(
                new TransientTdsErrorTdsServerArguments() 
                {
                  IsEnabledTransientError = true,
                  Number = errorCode,
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                Encrypt = SqlConnectionEncryptOption.Optional
            };

            using SqlConnection connection = new(builder.ConnectionString);
            await connection.OpenAsync();
            Assert.Equal(ConnectionState.Open, connection.State);
            Assert.Equal($"localhost,{server.EndPoint.Port}", connection.DataSource);
            Assert.Equal(2, server.PreLoginCount);
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(40613)]
        [InlineData(42108)]
        [InlineData(42109)]
        public void TransientFault_RetryEnabled_ShouldSucceed(uint errorCode)
        {
            using TransientTdsErrorTdsServer server = new(
                new TransientTdsErrorTdsServerArguments()
                {
                    IsEnabledTransientError = true,
                    Number = errorCode,
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                Encrypt = SqlConnectionEncryptOption.Optional
            };

            using SqlConnection connection = new(builder.ConnectionString);
            connection.Open();
            Assert.Equal(ConnectionState.Open, connection.State);
            Assert.Equal($"localhost,{server.EndPoint.Port}", connection.DataSource);
            Assert.Equal(2, server.PreLoginCount);
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(40613)]
        [InlineData(42108)]
        [InlineData(42109)]
        public async Task TransientFault_RetryDisabled_ShouldFail_Async(uint errorCode)
        {
            using TransientTdsErrorTdsServer server = new(
                new TransientTdsErrorTdsServerArguments()
                {
                    IsEnabledTransientError = true,
                    Number = errorCode,
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                ConnectRetryCount = 0,
                Encrypt = SqlConnectionEncryptOption.Optional
            };

            using SqlConnection connection = new(builder.ConnectionString);
            SqlException e = await Assert.ThrowsAsync<SqlException>(async () => await connection.OpenAsync());
            Assert.Equal((int)errorCode, e.Number);
            Assert.Equal(ConnectionState.Closed, connection.State);
            Assert.Equal(1, server.PreLoginCount);
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(40613)]
        [InlineData(42108)]
        [InlineData(42109)]
        public void TransientFault_RetryDisabled_ShouldFail(uint errorCode)
        {
            using TransientTdsErrorTdsServer server = new(
                new TransientTdsErrorTdsServerArguments()
                {
                    IsEnabledTransientError = true,
                    Number = errorCode,
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                ConnectRetryCount = 0,
                Encrypt = SqlConnectionEncryptOption.Optional
            };

            using SqlConnection connection = new(builder.ConnectionString);
            SqlException e = Assert.Throws<SqlException>(() => connection.Open());
            Assert.Equal((int)errorCode, e.Number);
            Assert.Equal(ConnectionState.Closed, connection.State);
            Assert.Equal(1, server.PreLoginCount);
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public async Task NetworkError_RetryEnabled_ShouldSucceed_Async(bool multiSubnetFailoverEnabled)
        {
            using TransientDelayTdsServer server = new(
                new TransientDelayTdsServerArguments()
                {
                    IsEnabledTransientDelay = true,
                    DelayDuration = TimeSpan.FromMilliseconds(1000),
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                Encrypt = SqlConnectionEncryptOption.Optional,
                ConnectTimeout = 5,
                MultiSubnetFailover = multiSubnetFailoverEnabled,
#if NETFRAMEWORK
                TransparentNetworkIPResolution = multiSubnetFailoverEnabled
#endif
            };

            using SqlConnection connection = new(builder.ConnectionString);
            await connection.OpenAsync();
            Assert.Equal(ConnectionState.Open, connection.State);
            Assert.Equal($"localhost,{server.EndPoint.Port}", connection.DataSource);
            if (multiSubnetFailoverEnabled)
            {
                Assert.True(server.PreLoginCount > 1, "Expected multiple pre-login attempts due to retry.");
            }
            else
            {
                Assert.Equal(1, server.PreLoginCount);
            }
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task NetworkDelay_RetryDisabled_Async(bool multiSubnetFailoverEnabled)
        {
            // Arrange
            using TransientDelayTdsServer server = new(
                new TransientDelayTdsServerArguments()
                {
                    IsEnabledTransientDelay = true,
                    DelayDuration = TimeSpan.FromMilliseconds(1000),
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                ConnectTimeout = 5,
                ConnectRetryCount = 0,
                Encrypt = SqlConnectionEncryptOption.Optional,
                MultiSubnetFailover = multiSubnetFailoverEnabled,
#if NETFRAMEWORK
                TransparentNetworkIPResolution = multiSubnetFailoverEnabled,
#endif
            };

            using SqlConnection connection = new(builder.ConnectionString);

            // Act
            await connection.OpenAsync();

            // Assert
            Assert.Equal(ConnectionState.Open, connection.State);
            Assert.Equal($"localhost,{server.EndPoint.Port}", connection.DataSource);

            if (multiSubnetFailoverEnabled)
            {
                Assert.True(server.PreLoginCount > 1, "Expected multiple pre-login attempts due to retry.");
            }
            else
            {
                Assert.Equal(1, server.PreLoginCount);
            }
        }

        [Trait("Category", "flaky")]
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void NetworkDelay_RetryDisabled(bool multiSubnetFailoverEnabled)
        {
            // Arrange
            using TransientDelayTdsServer server = new(
                new TransientDelayTdsServerArguments()
                {
                    IsEnabledTransientDelay = true,
                    DelayDuration = TimeSpan.FromMilliseconds(1000),
                });
            server.Start();
            SqlConnectionStringBuilder builder = new()
            {
                DataSource = "localhost," + server.EndPoint.Port,
                ConnectRetryCount = 0,
                Encrypt = SqlConnectionEncryptOption.Optional,
                ConnectTimeout = 5,
                MultiSubnetFailover = multiSubnetFailoverEnabled,
#if NETFRAMEWORK
                TransparentNetworkIPResolution = multiSubnetFailoverEnabled,
#endif
            };

            using SqlConnection connection = new(builder.ConnectionString);

            // Act
            connection.Open();

            // Assert
            Assert.Equal(ConnectionState.Open, connection.State);
            Assert.Equal($"localhost,{server.EndPoint.Port}", connection.DataSource);

            if (multiSubnetFailoverEnabled)
            {
                Assert.True(server.PreLoginCount > 1, "Expected multiple pre-login attempts due to retry.");
            }
            else
            {
                Assert.Equal(1, server.PreLoginCount);
            }
        }

        [Fact]
        public void SqlConnectionDbProviderFactoryTest()
        {
            SqlConnection con = new();
            PropertyInfo? dbProviderFactoryProperty = con.GetType().GetProperty("DbProviderFactory", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(dbProviderFactoryProperty);
            DbProviderFactory? factory = dbProviderFactoryProperty.GetValue(con) as DbProviderFactory;
            Assert.NotNull(factory);
            Assert.Same(typeof(SqlClientFactory), factory.GetType());
            Assert.Same(SqlClientFactory.Instance, factory);
        }

        [Fact]
        public void SqlConnectionValidParameters()
        {
            var con = new SqlConnection("Timeout=1234;packet Size=5678 ;;; ;");
            Assert.Equal(1234, con.ConnectionTimeout);
            Assert.Equal(5678, con.PacketSize);
        }

        [Fact]
        public void SqlConnectionEmptyParameters()
        {
            var con = new SqlConnection("Timeout=;packet Size= ;Integrated Security=;");
            //default values are defined in internal class DbConnectionStringDefaults
            Assert.Equal(15, con.ConnectionTimeout);
            Assert.Equal(8000, con.PacketSize);
            Assert.False(new SqlConnectionStringBuilder(con.ConnectionString).IntegratedSecurity);
        }

        [Theory]
        [InlineData("Timeout=null;")]
        [InlineData("Timeout= null;")]
        [InlineData("Timeout=1 1;")]
        [InlineData("Timeout=1a;")]
        [InlineData("Integrated Security=truee")]
        public void SqlConnectionInvalidParameters(string connString)
        {
            Assert.Throws<ArgumentException>(() => new SqlConnection(connString));
        }

        [Fact]
        public void ClosedConnectionSchemaRetrieval()
        {
            using SqlConnection connection = new(string.Empty);
            Assert.Throws<InvalidOperationException>(() => connection.GetSchema());
        }

        [Theory]
        [InlineData("RandomStringForTargetServer", false, true)]
        [InlineData("RandomStringForTargetServer", true, false)]
        [InlineData(null, false, false)]
        [InlineData("", false, false)]
        public void RetrieveWorkstationId(string? workstation, bool withDispose, bool shouldMatchSetWorkstationId)
        {
            string connectionString = $"Workstation Id={workstation}";
            SqlConnection conn = new(connectionString);
            if (withDispose)
            {
                conn.Dispose();
            }
            string? expected = shouldMatchSetWorkstationId ? workstation : Environment.MachineName;
            Assert.Equal(expected, conn.WorkstationId);
        }

        [OuterLoop("Can take up to 4 seconds")]
        [Fact]
        public void ExceptionsWithMinPoolSizeCanBeHandled()
        {
            string connectionString = $"Data Source={Guid.NewGuid()};uid=random;pwd=asd;Connect Timeout=2; Min Pool Size=3";
            for (int i = 0; i < 2; i++)
            {
                using SqlConnection connection = new(connectionString);
                Exception exception = Record.Exception(() => connection.Open());
                Assert.True(exception is InvalidOperationException || exception is SqlException, $"Unexpected exception: {exception}");
            }
        }

        [Fact]
        public void ConnectionTestInvalidCredentialCombination()
        {
            var cleartextCredsConnStr = "User=test;Password=test;";
            var sspiConnStr = "Integrated Security=true;";
            var testPassword = new SecureString();
            testPassword.MakeReadOnly();
            var sqlCredential = new SqlCredential(string.Empty, testPassword);

            // Verify that SSPI and cleartext username/password are not in the connection string.
            Assert.Throws<ArgumentException>(() => { new SqlConnection(cleartextCredsConnStr, sqlCredential); });

            Assert.Throws<ArgumentException>(() => { new SqlConnection(sspiConnStr, sqlCredential); });

            // Verify that credential may not be set with cleartext username/password or SSPI.
            using (var conn = new SqlConnection(cleartextCredsConnStr))
            {
                Assert.Throws<InvalidOperationException>(() => { conn.Credential = sqlCredential; });
            }

            using (var conn = new SqlConnection(sspiConnStr))
            {
                Assert.Throws<InvalidOperationException>(() => { conn.Credential = sqlCredential; });
            }

            // Verify that connection string with username/password or SSPI may not be set with credential present.
            using (var conn = new SqlConnection(string.Empty, sqlCredential))
            {
                Assert.Throws<InvalidOperationException>(() => { conn.ConnectionString = cleartextCredsConnStr; });

                Assert.Throws<InvalidOperationException>(() => { conn.ConnectionString = sspiConnStr; });
            }
        }

        [Theory]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryIntegrated)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryInteractive)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryManagedIdentity)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryMSI)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryDefault)]
        [InlineData(SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity)]
        public void ConnectionTestInvalidCredentialAndAuthentication(SqlAuthenticationMethod authentication)
        {
            var connectionString = $"Authentication={authentication}";

            using var testPassword = new SecureString();
            testPassword.MakeReadOnly();
            var credential = new SqlCredential(string.Empty, testPassword);

            Assert.Throws<ArgumentException>(() => new SqlConnection(connectionString, credential));

            // Attempt to set the credential after creation
            using var connection = new SqlConnection(connectionString);
            Assert.Throws<InvalidOperationException>(() => connection.Credential = credential);
        }

        [Fact]
        public void ConnectionTestValidCredentialCombination()
        {
            var testPassword = new SecureString();
            testPassword.MakeReadOnly();
            var sqlCredential = new SqlCredential(string.Empty, testPassword);
            var conn = new SqlConnection(string.Empty, sqlCredential);

            Assert.Equal(sqlCredential, conn.Credential);
        }


        [Theory]
        [InlineData(60)]
        [InlineData(10)]
        [InlineData(1)]
        public void ConnectionTimeoutTest(int timeout)
        {
            // Start a server with connection timeout from the inline data.
            //TODO: do we even need a server for this test?
            using TdsServer server = new();
            server.Start();
            var connStr = new SqlConnectionStringBuilder() {
                DataSource = $"localhost,{server.EndPoint.Port}",
                ConnectTimeout = timeout,
                Encrypt = SqlConnectionEncryptOption.Optional
            }.ConnectionString;
            using SqlConnection connection = new(connStr);

            // Dispose the server to force connection timeout 
            server.Dispose();

            // Measure the actual time it took to timeout and compare it with configured timeout
            Stopwatch timer = new();
            Exception? ex = null;

            // Open a connection with the server disposed.
            try
            {
                timer.Start();
                connection.Open();
            }
            catch (Exception e)
            {
                timer.Stop();
                ex = e;
            }

            Assert.False(timer.IsRunning, "Timer must be stopped.");
            Assert.NotNull(ex);
            Assert.True(timer.Elapsed.TotalSeconds <= timeout + 3,
                $"The actual timeout {timer.Elapsed.TotalSeconds} is expected to be less than {timeout} plus 3 seconds additional threshold." +
                $"{Environment.NewLine}{ex}");
        }

        [Theory]
        [InlineData(60)]
        [InlineData(10)]
        [InlineData(1)]
        public async Task ConnectionTimeoutTestAsync(int timeout)
        {
            // Start a server with connection timeout from the inline data.
            //TODO: do we even need a server for this test?
            using TdsServer server = new();
            server.Start();
            var connStr = new SqlConnectionStringBuilder()
            {
                DataSource = $"localhost,{server.EndPoint.Port}",
                ConnectTimeout = timeout,
                Encrypt = SqlConnectionEncryptOption.Optional
            }.ConnectionString;
            using SqlConnection connection = new(connStr);

            // Dispose the server to force connection timeout 
            server.Dispose();

            // Measure the actual time it took to timeout and compare it with configured timeout
            Stopwatch timer = new();
            Exception? ex = null;

            // Open a connection with the server disposed.
            try
            {
                //an asyn call with a timeout token to cancel the operation after the specific time
                using CancellationTokenSource cts = new(timeout * 1000);
                timer.Start();
                await connection.OpenAsync(cts.Token).ConfigureAwait(false);
            }
            catch (Exception e)
            {
                timer.Stop();
                ex = e;
            }

            Assert.False(timer.IsRunning, "Timer must be stopped.");
            Assert.NotNull(ex);
            Assert.True(timer.Elapsed.TotalSeconds <= timeout + 3,
                $"The actual timeout {timer.Elapsed.TotalSeconds} is expected to be less than {timeout} plus 3 seconds additional threshold." +
                $"{Environment.NewLine}{ex}");
        }

        [Fact]
        public void ConnectionInvalidTimeoutTest()
        {
            Assert.Throws<ArgumentException>(() =>
            {
                var connectionString = new SqlConnectionStringBuilder()
                {
                    DataSource = "localhost",
                    ConnectTimeout = -5 // Invalid timeout
                }.ConnectionString;
            });

        }

        [Fact]
        public void ConnectionTestWithCultureTH()
        {
            CultureInfo savedCulture = Thread.CurrentThread.CurrentCulture;
            CultureInfo savedUICulture = Thread.CurrentThread.CurrentUICulture;

            try
            {
                Thread.CurrentThread.CurrentCulture = new CultureInfo("th-TH");
                Thread.CurrentThread.CurrentUICulture = new CultureInfo("th-TH");

                //TODO: do we even need a server for this test?
                using TdsServer server = new();
                server.Start();
                var connStr = new SqlConnectionStringBuilder()
                {
                    DataSource = $"localhost,{server.EndPoint.Port}",
                    Encrypt = SqlConnectionEncryptOption.Optional
                }.ConnectionString;
                using SqlConnection connection = new(connStr);
                connection.Open();
                Assert.Equal(ConnectionState.Open, connection.State);
            }
            finally
            {
                // Restore saved cultures if necessary
                if (Thread.CurrentThread.CurrentCulture != savedCulture)
                {
                    Thread.CurrentThread.CurrentCulture = savedCulture;
                }

                if (Thread.CurrentThread.CurrentUICulture != savedUICulture)
                {
                    Thread.CurrentThread.CurrentUICulture = savedUICulture;
                }
            }
        }

        [Fact]
        public void ConnectionTestAccessTokenCallbackCombinations()
        {
            var cleartextCredsConnStr = "User=test;Password=test;";
            var sspiConnStr = "Integrated Security=true;";
            var authConnStr = "Authentication=ActiveDirectoryPassword";
            var testPassword = new SecureString();
            testPassword.MakeReadOnly();
            var sqlCredential = new SqlCredential(string.Empty, testPassword);
            Func<SqlAuthenticationParameters, CancellationToken, Task<SqlAuthenticationToken>> callback = (ctx, token) =>
                    Task.FromResult(new SqlAuthenticationToken("invalid", DateTimeOffset.MaxValue));

            // Successes
            using (var conn = new SqlConnection(cleartextCredsConnStr))
            {
                conn.AccessTokenCallback = callback;
                conn.AccessTokenCallback = null;
            }

            using (var conn = new SqlConnection(string.Empty, sqlCredential))
            {
                conn.AccessTokenCallback = null;
                conn.AccessTokenCallback = callback;
            }

            using (var conn = new SqlConnection()
            {
                AccessTokenCallback = callback
            })
            {
                conn.Credential = sqlCredential;
            }

            using (var conn = new SqlConnection()
            {
                AccessTokenCallback = callback
            })
            {
                conn.ConnectionString = cleartextCredsConnStr;
            }

            //Failures
            using (var conn = new SqlConnection(sspiConnStr))
            {
                Assert.Throws<InvalidOperationException>(() =>
                {
                    conn.AccessTokenCallback = callback;
                });
            }

            using (var conn = new SqlConnection(authConnStr))
            {
                Assert.Throws<InvalidOperationException>(() =>
                {
                    conn.AccessTokenCallback = callback;
                });
            }

            using (var conn = new SqlConnection()
            {
                AccessTokenCallback = callback
            })
            {
                Assert.Throws<InvalidOperationException>(() =>
                {
                    conn.ConnectionString = sspiConnStr;
                });
            }

            using (var conn = new SqlConnection()
            {
                AccessTokenCallback = callback
            })
            {
                Assert.Throws<InvalidOperationException>(() =>
                {
                    conn.ConnectionString = authConnStr;
                });
            }
        }

        [Theory]
        [InlineData(9, 0, 2047)] // SQL Server 2005
        [InlineData(10, 0, 2531)] // SQL Server 2008
        [InlineData(10, 50, 2500)] // SQL Server 2008 R2
        [InlineData(11, 0, 3000)] // SQL Server 2012-2022
        public void ConnectionTestPermittedVersion(int major, int minor, int build)
        {
            Version simulatedServerVersion = new(major, minor, build);

            using TdsServer server = new(
                new TdsServerArguments
                {
                    ServerVersion = simulatedServerVersion,
                });
            server.Start();
            var connStr = new SqlConnectionStringBuilder()
            {
                DataSource = $"localhost,{server.EndPoint.Port}",
                Encrypt = SqlConnectionEncryptOption.Optional,
            }.ConnectionString;
            using SqlConnection conn = new(connStr);

            conn.Open();
            Assert.Equal(ConnectionState.Open, conn.State);

            Version returnedServerVersion = Version.Parse(conn.ServerVersion);

            Assert.Equal(simulatedServerVersion, returnedServerVersion);
        }

        [Theory]
        [InlineData(7, 0, 623)] // SQL Server 7.0
        [InlineData(8, 0, 194)] // SQL Server 2000 RTM
        [InlineData(8, 0, 384)] // SQL Server 2000 SP1
        public void ConnectionTestDeniedVersion(int major, int minor, int build)
        {
            Version simulatedServerVersion = new(major, minor, build);
            using TdsServer server = new(
                new TdsServerArguments
                {
                    ServerVersion = simulatedServerVersion,
                });
            server.Start();
            var connStr = new SqlConnectionStringBuilder()
            {
                DataSource = $"localhost,{server.EndPoint.Port}",
                Encrypt = SqlConnectionEncryptOption.Optional,
            }.ConnectionString;
            using SqlConnection conn = new(connStr);

            Assert.Throws<InvalidOperationException>(() => conn.Open());
        }



        // Test to verify that the server and client negotiate
        // the common feature extension version.
        // MDS currently supports vector feature ext version 0x1.
        [Theory]
        [InlineData(true, 0x2, 0x1)]
        [InlineData(false, 0x0, 0x0)]
        [InlineData(true, 0x1, 0x1)]
        [InlineData(true, 0xFF, 0x0)]
        public void TestConnWithVectorFeatExtVersionNegotiation(bool expectedConnectionResult, byte serverVersion, byte expectedNegotiatedVersion)
        {
            // Start the test TDS server.
            using var server = new TdsServer();
            server.Start();
            server.ServerSupportedVectorFeatureExtVersion = serverVersion;
            server.EnableVectorFeatureExt = serverVersion == 0xFF ? false : true;

            byte expectedLoginReqFeatureExtId = (byte)TDSFeatureID.VectorSupport;
            byte expectedLoginReqFeatureExtVersion = 0x1;
            byte actualLoginReqFeatureExtId = 0;
            byte actualLoginReqFeatureExtVersion = 0;
            byte actualFeatureExtAckId = 0;
            byte actualFeatureExtAckVersion = 0;
            bool loginValuesFound = false;
            bool responseValuesFound = false;

            server.OnLogin7Validated = loginToken =>
            {
                if (loginToken.FeatureExt != null)
                {
                    var optionToken = loginToken.FeatureExt
                    .OfType<TDSLogin7GenericOptionToken>()
                    .FirstOrDefault(token => token.FeatureID == TDSFeatureID.VectorSupport);

                    if (optionToken != null)
                    {
                        actualLoginReqFeatureExtId = (byte)optionToken.FeatureID;
                        actualLoginReqFeatureExtVersion = optionToken.Data[0];
                        loginValuesFound = true;
                    }
                }
            };

            server.OnAuthenticationResponseCompleted = response =>
            {
                var featureExtAckToken = response
                .OfType<TDSFeatureExtAckToken>()
                .FirstOrDefault();

                if (featureExtAckToken != null)
                {
                    var featureExtensionOption = featureExtAckToken.Options
                    .OfType<TDSFeatureExtAckGenericOption>()
                    .FirstOrDefault(option => option.FeatureID == TDSFeatureID.VectorSupport);

                    if (featureExtensionOption != null)
                    {
                        actualFeatureExtAckId = (byte)featureExtensionOption.FeatureID;
                        actualFeatureExtAckVersion = featureExtensionOption.FeatureAckData[0];
                        responseValuesFound = true;
                    }
                }
            };

            // Connect to the test TDS server.
            var connStr = new SqlConnectionStringBuilder
            {
                DataSource = $"localhost,{server.EndPoint.Port}",
                Encrypt = SqlConnectionEncryptOption.Optional,
            }.ConnectionString;
            using var connection = new SqlConnection(connStr);
            if (expectedConnectionResult)
            {
                connection.Open();
                // Verify that the expected value was sent in the LOGIN packet.
                Assert.Equal(expectedLoginReqFeatureExtId, actualLoginReqFeatureExtId);
                Assert.Equal(expectedLoginReqFeatureExtVersion, actualLoginReqFeatureExtVersion);
                Assert.True(loginValuesFound, "Expected login values not found in the login packet.");
                // Verify that the expected values were received in the TDS response.
                if (server.EnableVectorFeatureExt)
                {
                    Assert.Equal(expectedLoginReqFeatureExtId, actualFeatureExtAckId);
                    Assert.Equal(expectedNegotiatedVersion, actualFeatureExtAckVersion);
                    Assert.True(responseValuesFound, "Expected response values not found in the login response.");
                }
                else
                {
                    Assert.Equal(0x0, actualFeatureExtAckId);
                    Assert.Equal(0x0, actualFeatureExtAckVersion);
                }
            }
            else
            {
                Assert.Throws<InvalidOperationException>(() => connection.Open());
            }
        }
    }
}
