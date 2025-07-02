// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Data.SqlClient.ManagedSni;

namespace Microsoft.Data.SqlClient
{
    sealed internal partial class TdsParser
    {
        internal void PostReadAsyncForMars()
        {
            // No-Op
        }

        private void LoadSSPILibrary()
        {
            // No - Op
        }

        private void WaitForSSLHandShakeToComplete(ref uint error, ref int protocolVersion)
        {
            // No - Op
        }

        private SNIErrorDetails GetSniErrorDetails()
        {
            SNIErrorDetails details;
            SniError sniError = SniProxy.Instance.GetLastError();
            details.sniErrorNumber = sniError.sniError;
            details.errorMessage = sniError.errorMessage;
            details.nativeError = sniError.nativeError;
            details.provider = (int)sniError.provider;
            details.lineNumber = sniError.lineNumber;
            details.function = sniError.function;
            details.exception = sniError.exception;
            
            return details;
        }

    }
}
