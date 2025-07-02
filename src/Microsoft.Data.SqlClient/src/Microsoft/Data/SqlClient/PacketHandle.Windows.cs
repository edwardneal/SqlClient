// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;

namespace Microsoft.Data.SqlClient
{
    // This structure is used for transporting packet handle references between the
    // TdsParserStateObject base class and Managed or Native implementations. 
    // It prevents the native IntPtr type from being boxed and prevents the need to cast from
    // object which loses compile time type safety.
    // It carries type information so that assertions about the type of handle can be made in the
    // implemented abstract methods. 
    // It is a ref struct so that it can only be used to transport the handles and not store them

    // N.B. If you change this type you must also change the version for the other platform

    internal readonly ref struct PacketHandle
    {
        /// <summary>
        /// PacketHandle is transporting a native pointer. The NativePointer field is valid.
        /// A PacketHandle has this type when managed code is referencing a pointer to a
        /// packet which has been read from the native SNI layer.
        /// </summary>
        public const int NativePointerType = 1;
        /// <summary>
        /// PacketHandle is transporting a native packet. The NativePacket field is valid.
        /// A PacketHandle has this type when managed code is directly referencing a packet
        /// which is due to be passed to the native SNI layer.
        /// </summary>
        public const int NativePacketType = 2;
        
        #if NET
        /// <summary>
        /// PacketHandle is transporting a managed packet. The ManagedPacket field is valid.
        /// A PacketHandle used by the managed SNI layer will always have this type.
        /// </summary>
        public const int ManagedPacketType = 3;

        public readonly ManagedSni.SniPacket ManagedPacket;
        #endif
        
        public readonly SNIPacket NativePacket;
        public readonly IntPtr NativePointer;
        public readonly int Type;

        #if NET
        private PacketHandle(IntPtr nativePointer, SNIPacket nativePacket, ManagedSni.SniPacket managedPacket, int type)
        {
            Type = type;
            ManagedPacket = managedPacket;
            NativePointer = nativePointer;
            NativePacket = nativePacket;
        }
        #else
        private PacketHandle(IntPtr nativePointer, SNIPacket nativePacket, int type)
        {
            Type = type;
            NativePointer = nativePointer;
            NativePacket = nativePacket;
        }
        #endif

        #if NET
        public static PacketHandle FromManagedPacket(ManagedSni.SniPacket managedPacket) =>
            new PacketHandle(default, default, managedPacket, ManagedPacketType);

        public static PacketHandle FromNativePointer(IntPtr nativePointer) =>
            new PacketHandle(nativePointer, default, default, NativePointerType);

        public static PacketHandle FromNativePacket(SNIPacket nativePacket) =>
            new PacketHandle(default, nativePacket, default, NativePacketType);
        #else
        public static PacketHandle FromNativePointer(IntPtr nativePointer) =>
            new PacketHandle(nativePointer, default, NativePointerType);

        public static PacketHandle FromNativePacket(SNIPacket nativePacket) =>
            new PacketHandle(default, nativePacket, NativePacketType);
        #endif
    }
}
