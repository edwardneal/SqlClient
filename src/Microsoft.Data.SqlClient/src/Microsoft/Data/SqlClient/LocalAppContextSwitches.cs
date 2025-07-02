// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.Data.SqlClient
{
    internal static partial class LocalAppContextSwitches
    {
        private enum Tristate : byte
        {
            NotInitialized = 0,
            False = 1,
            True = 2
        }

        internal const string MakeReadAsyncBlockingString = @"Switch.Microsoft.Data.SqlClient.MakeReadAsyncBlocking";
        internal const string LegacyRowVersionNullString = @"Switch.Microsoft.Data.SqlClient.LegacyRowVersionNullBehavior";
        internal const string SuppressInsecureTlsWarningString = @"Switch.Microsoft.Data.SqlClient.SuppressInsecureTLSWarning";
        internal const string UseMinimumLoginTimeoutString = @"Switch.Microsoft.Data.SqlClient.UseOneSecFloorInTimeoutCalculationDuringLogin";
        internal const string LegacyVarTimeZeroScaleBehaviourString = @"Switch.Microsoft.Data.SqlClient.LegacyVarTimeZeroScaleBehaviour";
        internal const string UseCompatibilityProcessSniString = @"Switch.Microsoft.Data.SqlClient.UseCompatibilityProcessSni";
        internal const string UseCompatibilityAsyncBehaviourString = @"Switch.Microsoft.Data.SqlClient.UseCompatibilityAsyncBehaviour";
        internal const string UseConnectionPoolV2String = @"Switch.Microsoft.Data.SqlClient.UseConnectionPoolV2";

        // this field is accessed through reflection in tests and should not be renamed or have the type changed without refactoring NullRow related tests
        private static Tristate s_legacyRowVersionNullBehavior;
        private static Tristate s_suppressInsecureTlsWarning;
        private static Tristate s_makeReadAsyncBlocking;
        private static Tristate s_useMinimumLoginTimeout;
        // this field is accessed through reflection in Microsoft.Data.SqlClient.Tests.SqlParameterTests and should not be renamed or have the type changed without refactoring related tests
        private static Tristate s_legacyVarTimeZeroScaleBehaviour;
        private static Tristate s_useCompatibilityProcessSni;
        private static Tristate s_useCompatibilityAsyncBehaviour;
        private static Tristate s_useConnectionPoolV2;

#if NET
        static LocalAppContextSwitches()
        {
            IAppContextSwitchOverridesSection appContextSwitch = AppConfigManager.FetchConfigurationSection<AppContextSwitchOverridesSection>(AppContextSwitchOverridesSection.Name);
            try
            {
                SqlAppContextSwitchManager.ApplyContextSwitches(appContextSwitch);
            }
            catch (Exception e)
            {
                // Don't throw an exception for an invalid config file
                SqlClientEventSource.Log.TryTraceEvent("<sc.{0}.ctor|INFO>: {1}", nameof(LocalAppContextSwitches), e);
            }
        }
#endif

#if NETFRAMEWORK
        internal const string DisableTnirByDefaultString = @"Switch.Microsoft.Data.SqlClient.DisableTNIRByDefaultInConnectionString";
        private static Tristate s_disableTnirByDefault;

        /// <summary>
        /// Transparent Network IP Resolution (TNIR) is a revision of the existing MultiSubnetFailover feature.
        /// TNIR affects the connection sequence of the driver in the case where the first resolved IP of the hostname
        /// doesn't respond and there are multiple IPs associated with the hostname.
        /// 
        /// TNIR interacts with MultiSubnetFailover to provide the following three connection sequences:
        /// 0: One IP is attempted, followed by all IPs in parallel
        /// 1: All IPs are attempted in parallel
        /// 2: All IPs are attempted one after another
        /// 
        /// TransparentNetworkIPResolution is enabled by default. MultiSubnetFailover is disabled by default.
        /// To disable TNIR, you can enable the app context switch.
        /// 
        /// This app context switch defaults to 'false'.
        /// </summary>
        public static bool DisableTnirByDefault
        {
            get
            {
                if (s_disableTnirByDefault == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(DisableTnirByDefaultString, out bool returnedValue) && returnedValue)
                    {
                        s_disableTnirByDefault = Tristate.True;
                    }
                    else
                    {
                        s_disableTnirByDefault = Tristate.False;
                    }
                }
                return s_disableTnirByDefault == Tristate.True;
            }
        }
#endif
        /// <summary>
        /// In TdsParser the ProcessSni function changed significantly when the packet
        /// multiplexing code needed for high speed multi-packet column values was added.
        /// In case of compatibility problems this switch will change TdsParser to use
        /// the previous version of the function.
        /// </summary>
        public static bool UseCompatibilityProcessSni
        {
            get
            {
                if (s_useCompatibilityProcessSni == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(UseCompatibilityProcessSniString, out bool returnedValue) && returnedValue)
                    {
                        s_useCompatibilityProcessSni = Tristate.True;
                    }
                    else
                    {
                        s_useCompatibilityProcessSni = Tristate.False;
                    }
                }
                return s_useCompatibilityProcessSni == Tristate.True;
            }
        }

        /// <summary>
        /// In TdsParser the async multi-packet column value fetch behaviour is capable of
        /// using a continue snapshot state in addition to the original replay from start
        /// logic.
        /// This switch disables use of the continue snapshot state. This switch will always
        /// return true if <see cref="UseCompatibilityProcessSni"/> is enabled because the 
        /// continue state is not stable without the multiplexer.
        /// </summary>
        public static bool UseCompatibilityAsyncBehaviour
        {
            get
            {
                if (UseCompatibilityProcessSni)
                {
                    // If ProcessSni compatibility mode has been enabled then the packet
                    // multiplexer has been disabled. The new async behaviour using continue
                    // point capture is only stable if the multiplexer is enabled so we must
                    // return true to enable compatibility async behaviour using only restarts.
                    return true;
                }

                if (s_useCompatibilityAsyncBehaviour == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(UseCompatibilityAsyncBehaviourString, out bool returnedValue) && returnedValue)
                    {
                        s_useCompatibilityAsyncBehaviour = Tristate.True;
                    }
                    else
                    {
                        s_useCompatibilityAsyncBehaviour = Tristate.False;
                    }
                }
                return s_useCompatibilityAsyncBehaviour == Tristate.True;
            }
        }

        /// <summary>
        /// When using Encrypt=false in the connection string, a security warning is output to the console if the TLS version is 1.2 or lower.
        /// This warning can be suppressed by enabling this AppContext switch.
        /// This app context switch defaults to 'false'.
        /// </summary>
        public static bool SuppressInsecureTlsWarning
        {
            get
            {
                if (s_suppressInsecureTlsWarning == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(SuppressInsecureTlsWarningString, out bool returnedValue) && returnedValue)
                    {
                        s_suppressInsecureTlsWarning = Tristate.True;
                    }
                    else
                    {
                        s_suppressInsecureTlsWarning = Tristate.False;
                    }
                }
                return s_suppressInsecureTlsWarning == Tristate.True;
            }
        }

        /// <summary>
        /// In System.Data.SqlClient and Microsoft.Data.SqlClient prior to 3.0.0 a field with type Timestamp/RowVersion
        /// would return an empty byte array. This switch controls whether to preserve that behaviour on newer versions
        /// of Microsoft.Data.SqlClient, if this switch returns false an appropriate null value will be returned.
        /// This app context switch defaults to 'false'.
        /// </summary>
        public static bool LegacyRowVersionNullBehavior
        {
            get
            {
                if (s_legacyRowVersionNullBehavior == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(LegacyRowVersionNullString, out bool returnedValue) && returnedValue)
                    {
                        s_legacyRowVersionNullBehavior = Tristate.True;
                    }
                    else
                    {
                        s_legacyRowVersionNullBehavior = Tristate.False;
                    }
                }
                return s_legacyRowVersionNullBehavior == Tristate.True;
            }
        }

        /// <summary>
        /// When enabled, ReadAsync runs asynchronously and does not block the calling thread.
        /// This app context switch defaults to 'false'.
        /// </summary>
        public static bool MakeReadAsyncBlocking
        {
            get
            {
                if (s_makeReadAsyncBlocking == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(MakeReadAsyncBlockingString, out bool returnedValue) && returnedValue)
                    {
                        s_makeReadAsyncBlocking = Tristate.True;
                    }
                    else
                    {
                        s_makeReadAsyncBlocking = Tristate.False;
                    }
                }
                return s_makeReadAsyncBlocking == Tristate.True;
            }
        }

        /// <summary>
        /// Specifies minimum login timeout to be set to 1 second instead of 0 seconds,
        /// to prevent a login attempt from waiting indefinitely.
        /// This app context switch defaults to 'true'.
        /// </summary>
        public static bool UseMinimumLoginTimeout
        {
            get
            {
                if (s_useMinimumLoginTimeout == Tristate.NotInitialized)
                {
                    if (!AppContext.TryGetSwitch(UseMinimumLoginTimeoutString, out bool returnedValue) || returnedValue)
                    {
                        s_useMinimumLoginTimeout = Tristate.True;
                    }
                    else
                    {
                        s_useMinimumLoginTimeout = Tristate.False;
                    }
                }
                return s_useMinimumLoginTimeout == Tristate.True;
            }
        }


        /// <summary>
        /// When set to 'true' this will output a scale value of 7 (DEFAULT_VARTIME_SCALE) when the scale 
        /// is explicitly set to zero for VarTime data types ('datetime2', 'datetimeoffset' and 'time')
        /// If no scale is set explicitly it will continue to output scale of 7 (DEFAULT_VARTIME_SCALE)
        /// regardsless of switch value.
        /// This app context switch defaults to 'true'.
        /// </summary>
        public static bool LegacyVarTimeZeroScaleBehaviour
        {
            get
            {
                if (s_legacyVarTimeZeroScaleBehaviour == Tristate.NotInitialized)
                {
                    if (!AppContext.TryGetSwitch(LegacyVarTimeZeroScaleBehaviourString, out bool returnedValue))
                    {
                        s_legacyVarTimeZeroScaleBehaviour = Tristate.True;
                    }
                    else
                    {
                        s_legacyVarTimeZeroScaleBehaviour = returnedValue ? Tristate.True : Tristate.False;
                    }
                }
                return s_legacyVarTimeZeroScaleBehaviour == Tristate.True;
            }
        }

        /// <summary>
        /// When set to true, the connection pool will use the new V2 connection pool implementation.
        /// When set to false, the connection pool will use the legacy V1 implementation.
        /// This app context switch defaults to 'false'.
        /// </summary>
        public static bool UseConnectionPoolV2
        {
            get
            {
                if (s_useConnectionPoolV2 == Tristate.NotInitialized)
                {
                    if (AppContext.TryGetSwitch(UseConnectionPoolV2String, out bool returnedValue) && returnedValue)
                    {
                        s_useConnectionPoolV2 = Tristate.True;
                    }
                    else
                    {
                        s_useConnectionPoolV2 = Tristate.False;
                    }
                }
                return s_useConnectionPoolV2 == Tristate.True;
            }
        }
    }
}
