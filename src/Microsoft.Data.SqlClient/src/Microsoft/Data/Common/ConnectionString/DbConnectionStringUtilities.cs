// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Common.ConnectionString;
using Microsoft.Data.SqlClient;

namespace Microsoft.Data.Common
{
    internal static class DbConnectionStringUtilities
    {
        internal static bool ConvertToBoolean(object value)
        {
            Debug.Assert(value != null, "ConvertToBoolean(null)");
            if (value is string svalue)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(svalue, "true") || StringComparer.OrdinalIgnoreCase.Equals(svalue, "yes"))
                {
                    return true;
                }
                else if (StringComparer.OrdinalIgnoreCase.Equals(svalue, "false") || StringComparer.OrdinalIgnoreCase.Equals(svalue, "no"))
                {
                    return false;
                }
                else
                {
                    string tmp = svalue.Trim();  // Remove leading & trailing white space.
                    if (StringComparer.OrdinalIgnoreCase.Equals(tmp, "true") || StringComparer.OrdinalIgnoreCase.Equals(tmp, "yes"))
                    {
                        return true;
                    }
                    else if (StringComparer.OrdinalIgnoreCase.Equals(tmp, "false") || StringComparer.OrdinalIgnoreCase.Equals(tmp, "no"))
                    {
                        return false;
                    }
                }
                return bool.Parse(svalue);
            }
            try
            {
                return Convert.ToBoolean(value, CultureInfo.InvariantCulture);
            }
            catch (InvalidCastException e)
            {
                throw ADP.ConvertFailed(value.GetType(), typeof(bool), e);
            }
        }

        internal static bool ConvertToIntegratedSecurity(object value)
        {
            Debug.Assert(value != null, "ConvertToIntegratedSecurity(null)");
            if (value is string svalue)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(svalue, "sspi") || StringComparer.OrdinalIgnoreCase.Equals(svalue, "true") || StringComparer.OrdinalIgnoreCase.Equals(svalue, "yes"))
                    return true;
                else if (StringComparer.OrdinalIgnoreCase.Equals(svalue, "false") || StringComparer.OrdinalIgnoreCase.Equals(svalue, "no"))
                    return false;
                else
                {
                    string tmp = svalue.Trim();  // Remove leading & trailing white space.
                    if (StringComparer.OrdinalIgnoreCase.Equals(tmp, "sspi") || StringComparer.OrdinalIgnoreCase.Equals(tmp, "true") || StringComparer.OrdinalIgnoreCase.Equals(tmp, "yes"))
                        return true;
                    else if (StringComparer.OrdinalIgnoreCase.Equals(tmp, "false") || StringComparer.OrdinalIgnoreCase.Equals(tmp, "no"))
                        return false;
                }
                return bool.Parse(svalue);
            }
            try
            {
                return Convert.ToBoolean(value, CultureInfo.InvariantCulture);
            }
            catch (InvalidCastException e)
            {
                throw ADP.ConvertFailed(value.GetType(), typeof(bool), e);
            }
        }

        internal static int ConvertToInt32(object value)
        {
            try
            {
                return Convert.ToInt32(value, CultureInfo.InvariantCulture);
            }
            catch (InvalidCastException e)
            {
                throw ADP.ConvertFailed(value.GetType(), typeof(int), e);
            }
        }

        internal static string ConvertToString(object value)
        {
            try
            {
                return Convert.ToString(value, CultureInfo.InvariantCulture);
            }
            catch (InvalidCastException e)
            {
                throw ADP.ConvertFailed(value.GetType(), typeof(string), e);
            }
        }

        internal static bool TryConvertToApplicationIntent(string value, out ApplicationIntent result)
        {
            Debug.Assert(Enum.GetNames(typeof(ApplicationIntent)).Length == 2, "ApplicationIntent enum has changed, update needed");
            Debug.Assert(value != null, "TryConvertToApplicationIntent(null,...)");

            if (StringComparer.OrdinalIgnoreCase.Equals(value, nameof(ApplicationIntent.ReadOnly)))
            {
                result = ApplicationIntent.ReadOnly;
                return true;
            }
            else if (StringComparer.OrdinalIgnoreCase.Equals(value, nameof(ApplicationIntent.ReadWrite)))
            {
                result = ApplicationIntent.ReadWrite;
                return true;
            }
            else
            {
                result = DbConnectionStringDefaults.ApplicationIntent;
                return false;
            }
        }

        internal static bool IsValidApplicationIntentValue(ApplicationIntent value)
        {
            Debug.Assert(Enum.GetNames(typeof(ApplicationIntent)).Length == 2, "ApplicationIntent enum has changed, update needed");
            return value == ApplicationIntent.ReadOnly || value == ApplicationIntent.ReadWrite;
        }

        internal static string ApplicationIntentToString(ApplicationIntent value)
        {
            Debug.Assert(IsValidApplicationIntentValue(value));
            if (value == ApplicationIntent.ReadOnly)
            {
                return nameof(ApplicationIntent.ReadOnly);
            }
            else
            {
                return nameof(ApplicationIntent.ReadWrite);
            }
        }

        /// <summary>
        /// This method attempts to convert the given value tp ApplicationIntent enum. The algorithm is:
        /// * if the value is from type string, it will be matched against ApplicationIntent enum names only, using ordinal, case-insensitive comparer
        /// * if the value is from type ApplicationIntent, it will be used as is
        /// * if the value is from integral type (SByte, Int16, Int32, Int64, Byte, UInt16, UInt32, or UInt64), it will be converted to enum
        /// * if the value is another enum or any other type, it will be blocked with an appropriate ArgumentException
        ///
        /// in any case above, if the converted value is out of valid range, the method raises ArgumentOutOfRangeException.
        /// </summary>
        /// <returns>application intent value in the valid range</returns>
        internal static ApplicationIntent ConvertToApplicationIntent(string keyword, object value)
        {
            Debug.Assert(value != null, "ConvertToApplicationIntent(null)");
            if (value is string sValue)
            {
                // We could use Enum.TryParse<ApplicationIntent> here, but it accepts value combinations like
                // "ReadOnly, ReadWrite" which are unwelcome here
                // Also, Enum.TryParse is 100x slower than plain StringComparer.OrdinalIgnoreCase.Equals method.

                if (TryConvertToApplicationIntent(sValue, out ApplicationIntent result))
                {
                    return result;
                }

                // try again after remove leading & trailing whitespaces.
                sValue = sValue.Trim();
                if (TryConvertToApplicationIntent(sValue, out result))
                {
                    return result;
                }

                // string values must be valid
                throw ADP.InvalidConnectionOptionValue(keyword);
            }
            else
            {
                // the value is not string, try other options
                ApplicationIntent eValue;

                if (value is ApplicationIntent intent)
                {
                    // quick path for the most common case
                    eValue = intent;
                }
                else if (value.GetType().IsEnum)
                {
                    // explicitly block scenarios in which user tries to use wrong enum types, like:
                    // builder["ApplicationIntent"] = EnvironmentVariableTarget.Process;
                    // workaround: explicitly cast non-ApplicationIntent enums to int
                    throw ADP.ConvertFailed(value.GetType(), typeof(ApplicationIntent), null);
                }
                else
                {
                    try
                    {
                        // Enum.ToObject allows only integral and enum values (enums are blocked above), raising ArgumentException for the rest
                        eValue = (ApplicationIntent)Enum.ToObject(typeof(ApplicationIntent), value);
                    }
                    catch (ArgumentException e)
                    {
                        // to be consistent with the messages we send in case of wrong type usage, replace
                        // the error with our exception, and keep the original one as inner one for troubleshooting
                        throw ADP.ConvertFailed(value.GetType(), typeof(ApplicationIntent), e);
                    }
                }

                // ensure value is in valid range
                if (IsValidApplicationIntentValue(eValue))
                {
                    return eValue;
                }
                else
                {
                    throw ADP.InvalidEnumerationValue(typeof(ApplicationIntent), (int)eValue);
                }
            }
        }

        const string SqlPasswordString = "Sql Password";
        [Obsolete("ActiveDirectoryPassword is deprecated.")]
        const string ActiveDirectoryPasswordString = "Active Directory Password";
        const string ActiveDirectoryIntegratedString = "Active Directory Integrated";
        const string ActiveDirectoryInteractiveString = "Active Directory Interactive";
        const string ActiveDirectoryServicePrincipalString = "Active Directory Service Principal";
        const string ActiveDirectoryDeviceCodeFlowString = "Active Directory Device Code Flow";
        internal const string ActiveDirectoryManagedIdentityString = "Active Directory Managed Identity";
        internal const string ActiveDirectoryMSIString = "Active Directory MSI";
        internal const string ActiveDirectoryDefaultString = "Active Directory Default";
        internal const string ActiveDirectoryWorkloadIdentityString = "Active Directory Workload Identity";

#if DEBUG
        private static readonly string[] s_supportedAuthenticationModes =
        {
            "NotSpecified",
            "SqlPassword",
            "ActiveDirectoryPassword",
            "ActiveDirectoryIntegrated",
            "ActiveDirectoryInteractive",
            "ActiveDirectoryServicePrincipal",
            "ActiveDirectoryDeviceCodeFlow",
            "ActiveDirectoryManagedIdentity",
            "ActiveDirectoryMSI",
            "ActiveDirectoryDefault",
            "ActiveDirectoryWorkloadIdentity",
        };

        private static bool IsValidAuthenticationMethodEnum()
        {
            string[] names = Enum.GetNames(typeof(SqlAuthenticationMethod));
            int l = s_supportedAuthenticationModes.Length;
            bool listValid;
            if (listValid = names.Length == l)
            {
                for (int i = 0; i < l; i++)
                {
                    if (string.Compare(s_supportedAuthenticationModes[i], names[i], StringComparison.Ordinal) != 0)
                    {
                        listValid = false;
                    }
                }
            }
            return listValid;
        }
#endif

        internal static bool TryConvertToAuthenticationType(string value, out SqlAuthenticationMethod result)
        {
#if DEBUG
            Debug.Assert(IsValidAuthenticationMethodEnum(), "SqlAuthenticationMethod enum has changed, update needed");
#endif
            bool isSuccess = false;

            if (StringComparer.InvariantCultureIgnoreCase.Equals(value, SqlPasswordString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.SqlPassword, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.SqlPassword;
                isSuccess = true;
            }
            #pragma warning disable 0618
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryPasswordString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryPassword, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryPassword;
            #pragma warning restore 0618
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryIntegratedString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryIntegrated, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryIntegrated;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryInteractiveString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryInteractive, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryInteractive;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryServicePrincipalString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryServicePrincipal, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryServicePrincipal;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryDeviceCodeFlowString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryManagedIdentityString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryManagedIdentity, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryManagedIdentity;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryMSIString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryMSI, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryMSI;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryDefaultString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryDefault, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryDefault;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, ActiveDirectoryWorkloadIdentityString)
                || StringComparer.InvariantCultureIgnoreCase.Equals(value, Convert.ToString(SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity, CultureInfo.InvariantCulture)))
            {
                result = SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity;
                isSuccess = true;
            }
            else
            {
                result = DbConnectionStringDefaults.Authentication;
            }
            return isSuccess;
        }

        /// <summary>
        /// Convert a string value to the corresponding SqlConnectionColumnEncryptionSetting.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="result"></param>
        /// <returns></returns>
        internal static bool TryConvertToColumnEncryptionSetting(string value, out SqlConnectionColumnEncryptionSetting result)
        {
            bool isSuccess = false;

            if (StringComparer.InvariantCultureIgnoreCase.Equals(value, nameof(SqlConnectionColumnEncryptionSetting.Enabled)))
            {
                result = SqlConnectionColumnEncryptionSetting.Enabled;
                isSuccess = true;
            }
            else if (StringComparer.InvariantCultureIgnoreCase.Equals(value, nameof(SqlConnectionColumnEncryptionSetting.Disabled)))
            {
                result = SqlConnectionColumnEncryptionSetting.Disabled;
                isSuccess = true;
            }
            else
            {
                result = DbConnectionStringDefaults.ColumnEncryptionSetting;
            }

            return isSuccess;
        }

        /// <summary>
        /// Is it a valid connection level column encryption setting ?
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static bool IsValidColumnEncryptionSetting(SqlConnectionColumnEncryptionSetting value)
        {
            Debug.Assert(Enum.GetNames(typeof(SqlConnectionColumnEncryptionSetting)).Length == 2, "SqlConnectionColumnEncryptionSetting enum has changed, update needed");
            return value == SqlConnectionColumnEncryptionSetting.Enabled || value == SqlConnectionColumnEncryptionSetting.Disabled;
        }

        /// <summary>
        /// Convert connection level column encryption setting value to string.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static string ColumnEncryptionSettingToString(SqlConnectionColumnEncryptionSetting value)
        {
            Debug.Assert(IsValidColumnEncryptionSetting(value), "value is not a valid connection level column encryption setting.");

            return value switch
            {
                SqlConnectionColumnEncryptionSetting.Enabled => nameof(SqlConnectionColumnEncryptionSetting.Enabled),
                SqlConnectionColumnEncryptionSetting.Disabled => nameof(SqlConnectionColumnEncryptionSetting.Disabled),
                _ => null,
            };
        }

        internal static bool IsValidAuthenticationTypeValue(SqlAuthenticationMethod value)
        {
            Debug.Assert(Enum.GetNames(typeof(SqlAuthenticationMethod)).Length == 11, "SqlAuthenticationMethod enum has changed, update needed");
            return value == SqlAuthenticationMethod.SqlPassword
                #pragma warning disable 0618
                || value == SqlAuthenticationMethod.ActiveDirectoryPassword
                #pragma warning restore 0618
                || value == SqlAuthenticationMethod.ActiveDirectoryIntegrated
                || value == SqlAuthenticationMethod.ActiveDirectoryInteractive
                || value == SqlAuthenticationMethod.ActiveDirectoryServicePrincipal
                || value == SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow
                || value == SqlAuthenticationMethod.ActiveDirectoryManagedIdentity
                || value == SqlAuthenticationMethod.ActiveDirectoryMSI
                || value == SqlAuthenticationMethod.ActiveDirectoryDefault
                || value == SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity
                || value == SqlAuthenticationMethod.NotSpecified;
        }

        internal static string AuthenticationTypeToString(SqlAuthenticationMethod value)
        {
            Debug.Assert(IsValidAuthenticationTypeValue(value));

            return value switch
            {
                SqlAuthenticationMethod.SqlPassword => SqlPasswordString,
                #pragma warning disable 0618
                SqlAuthenticationMethod.ActiveDirectoryPassword => ActiveDirectoryPasswordString,
                #pragma warning restore 0618
                SqlAuthenticationMethod.ActiveDirectoryIntegrated => ActiveDirectoryIntegratedString,
                SqlAuthenticationMethod.ActiveDirectoryInteractive => ActiveDirectoryInteractiveString,
                SqlAuthenticationMethod.ActiveDirectoryServicePrincipal => ActiveDirectoryServicePrincipalString,
                SqlAuthenticationMethod.ActiveDirectoryDeviceCodeFlow => ActiveDirectoryDeviceCodeFlowString,
                SqlAuthenticationMethod.ActiveDirectoryManagedIdentity => ActiveDirectoryManagedIdentityString,
                SqlAuthenticationMethod.ActiveDirectoryMSI => ActiveDirectoryMSIString,
                SqlAuthenticationMethod.ActiveDirectoryDefault => ActiveDirectoryDefaultString,
                SqlAuthenticationMethod.ActiveDirectoryWorkloadIdentity => ActiveDirectoryWorkloadIdentityString,
                _ => null
            };
        }

        internal static SqlAuthenticationMethod ConvertToAuthenticationType(string keyword, object value)
        {
            if (value == null)
            {
                return DbConnectionStringDefaults.Authentication;
            }

            if (value is string sValue)
            {
                if (TryConvertToAuthenticationType(sValue, out SqlAuthenticationMethod result))
                {
                    return result;
                }

                // try again after remove leading & trailing whitespaces.
                sValue = sValue.Trim();
                if (TryConvertToAuthenticationType(sValue, out result))
                {
                    return result;
                }

                // string values must be valid
                throw ADP.InvalidConnectionOptionValue(keyword);
            }
            else
            {
                // the value is not string, try other options
                SqlAuthenticationMethod eValue;

                if (value is SqlAuthenticationMethod method)
                {
                    // quick path for the most common case
                    eValue = method;
                }
                else if (value.GetType().IsEnum)
                {
                    // explicitly block scenarios in which user tries to use wrong enum types, like:
                    // builder["ApplicationIntent"] = EnvironmentVariableTarget.Process;
                    // workaround: explicitly cast non-ApplicationIntent enums to int
                    throw ADP.ConvertFailed(value.GetType(), typeof(SqlAuthenticationMethod), null);
                }
                else
                {
                    try
                    {
                        // Enum.ToObject allows only integral and enum values (enums are blocked above), raising ArgumentException for the rest
                        eValue = (SqlAuthenticationMethod)Enum.ToObject(typeof(SqlAuthenticationMethod), value);
                    }
                    catch (ArgumentException e)
                    {
                        // to be consistent with the messages we send in case of wrong type usage, replace
                        // the error with our exception, and keep the original one as inner one for troubleshooting
                        throw ADP.ConvertFailed(value.GetType(), typeof(SqlAuthenticationMethod), e);
                    }
                }

                // ensure value is in valid range
                if (IsValidAuthenticationTypeValue(eValue))
                {
                    return eValue;
                }
                else
                {
                    throw ADP.InvalidEnumerationValue(typeof(SqlAuthenticationMethod), (int)eValue);
                }
            }
        }

        /// <summary>
        /// Convert the provided value to a SqlConnectionColumnEncryptionSetting.
        /// </summary>
        /// <param name="keyword"></param>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static SqlConnectionColumnEncryptionSetting ConvertToColumnEncryptionSetting(string keyword, object value)
        {
            if (value == null)
            {
                return DbConnectionStringDefaults.ColumnEncryptionSetting;
            }

            if (value is string sValue)
            {
                if (TryConvertToColumnEncryptionSetting(sValue, out SqlConnectionColumnEncryptionSetting result))
                {
                    return result;
                }

                // try again after remove leading & trailing whitespaces.
                sValue = sValue.Trim();
                if (TryConvertToColumnEncryptionSetting(sValue, out result))
                {
                    return result;
                }

                // string values must be valid
                throw ADP.InvalidConnectionOptionValue(keyword);
            }
            else
            {
                // the value is not string, try other options
                SqlConnectionColumnEncryptionSetting eValue;

                if (value is SqlConnectionColumnEncryptionSetting setting)
                {
                    // quick path for the most common case
                    eValue = setting;
                }
                else if (value.GetType().IsEnum)
                {
                    // explicitly block scenarios in which user tries to use wrong enum types, like:
                    // builder["SqlConnectionColumnEncryptionSetting"] = EnvironmentVariableTarget.Process;
                    // workaround: explicitly cast non-SqlConnectionColumnEncryptionSetting enums to int
                    throw ADP.ConvertFailed(value.GetType(), typeof(SqlConnectionColumnEncryptionSetting), null);
                }
                else
                {
                    try
                    {
                        // Enum.ToObject allows only integral and enum values (enums are blocked above), raising ArgumentException for the rest
                        eValue = (SqlConnectionColumnEncryptionSetting)Enum.ToObject(typeof(SqlConnectionColumnEncryptionSetting), value);
                    }
                    catch (ArgumentException e)
                    {
                        // to be consistent with the messages we send in case of wrong type usage, replace
                        // the error with our exception, and keep the original one as inner one for troubleshooting
                        throw ADP.ConvertFailed(value.GetType(), typeof(SqlConnectionColumnEncryptionSetting), e);
                    }
                }

                // ensure value is in valid range
                if (IsValidColumnEncryptionSetting(eValue))
                {
                    return eValue;
                }
                else
                {
                    throw ADP.InvalidEnumerationValue(typeof(SqlConnectionColumnEncryptionSetting), (int)eValue);
                }
            }
        }
    }

    

    

    
}
