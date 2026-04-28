// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;

namespace Microsoft.Data.SqlClient.AlwaysEncrypted
{
    /// <summary>
    /// Encryption key class containing 4 keys. This class is used by SqlAeadAes256CbcHmac256Algorithm
    /// 1) root key - Main key that is used to derive the keys used in the encryption algorithm
    /// 2) encryption key - A derived key that is used to encrypt the plain text and generate cipher text
    /// 3) mac_key - A derived key that is used to compute HMAC of the cipher text
    /// 4) iv_key - A derived key that is used to generate a synthetic IV from plain text data.
    /// </summary>
    internal sealed class AeadAes256CbcHmac256EncryptionKey : SymmetricKey
    {
        /// <summary>
        /// Key size in bits.
        /// </summary>
        public const int KeySizeInBits = 256;

        /// <summary>
        /// Key size in bytes.
        /// </summary>
        public const int KeySizeInBytes = KeySizeInBits / 8;

        /// <summary>
        /// Encryption Key Salt format. This is used to derive the encryption key from the root key.
        /// </summary>
        private const string _encryptionKeySaltFormat = @"Microsoft SQL Server cell encryption key with encryption algorithm:{0} and key length:{1}";

        /// <summary>
        /// MAC Key Salt format. This is used to derive the MAC key from the root key.
        /// </summary>
        private const string _macKeySaltFormat = @"Microsoft SQL Server cell MAC key with encryption algorithm:{0} and key length:{1}";

        /// <summary>
        /// IV Key Salt format. This is used to derive the IV key from the root key. This is only used for Deterministic encryption.
        /// </summary>
        private const string _ivKeySaltFormat = @"Microsoft SQL Server cell IV key with encryption algorithm:{0} and key length:{1}";

        /// <summary>
        /// Derives all the required keys from the given root key
        /// </summary>
        /// <param name="rootKey">Root key used to derive all the required derived keys</param>
        internal AeadAes256CbcHmac256EncryptionKey(byte[] rootKey) : base(rootKey)
        {
            // Key validation
            if (rootKey.Length != KeySizeInBytes)
            {
                throw SQL.InvalidKeySize(SqlAeadAes256CbcHmac256Algorithm.AlgorithmName,
                                         rootKey.Length,
                                         KeySizeInBytes);
            }

            // Derive keys from the root key
            //
            // Derive encryption key
            string encryptionKeySalt = string.Format(_encryptionKeySaltFormat,
                                                    SqlAeadAes256CbcHmac256Algorithm.AlgorithmName,
                                                    KeySizeInBits);
            byte[] buff1 = new byte[KeySizeInBytes];
            SqlSecurityUtility.GetHMACWithSHA256(Encoding.Unicode.GetBytes(encryptionKeySalt), RootKey, buff1);
            EncryptionKey = buff1;

            // Derive mac key
            string macKeySalt = string.Format(_macKeySaltFormat, SqlAeadAes256CbcHmac256Algorithm.AlgorithmName, KeySizeInBits);
            byte[] buff2 = new byte[KeySizeInBytes];
            SqlSecurityUtility.GetHMACWithSHA256(Encoding.Unicode.GetBytes(macKeySalt), RootKey, buff2);
            MACKey = buff2;

            // Derive iv key
            string ivKeySalt = string.Format(_ivKeySaltFormat, SqlAeadAes256CbcHmac256Algorithm.AlgorithmName, KeySizeInBits);
            byte[] buff3 = new byte[KeySizeInBytes];
            SqlSecurityUtility.GetHMACWithSHA256(Encoding.Unicode.GetBytes(ivKeySalt), RootKey, buff3);
            IVKey = buff3;
        }

        /// <summary>
        /// Encryption key should be used for encryption and decryption
        /// </summary>
        public byte[] EncryptionKey { get; }

        /// <summary>
        /// MAC key should be used to compute and validate HMAC
        /// </summary>
        public byte[] MACKey { get; }

        /// <summary>
        /// IV key should be used to compute synthetic IV from a given plain text
        /// </summary>
        public byte[] IVKey { get; }
    }
}
