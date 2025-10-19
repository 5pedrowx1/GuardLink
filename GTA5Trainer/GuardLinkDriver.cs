using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GTATrainer
{
    public class GuardLinkDriver : IDisposable
    {
        // ==================== CONSTANTS ====================

        private const string DEVICE_PATH = @"\\.\Global\GuardLink";

        private const uint IOCTL_READ_MEMORY = 0x222008;   // CTL_CODE(0x8000, 2, 0, 0)
        private const uint IOCTL_WRITE_MEMORY = 0x22200C;  // CTL_CODE(0x8000, 3, 0, 0)
        private const uint IOCTL_GET_MODULE = 0x222010;    // CTL_CODE(0x8000, 4, 0, 0)

        // ==================== STRUCTURES ====================

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MEMORY_OPERATION
        {
            public IntPtr ProcessId;
            public IntPtr Address;
            public ulong Size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
        public struct MODULE_REQUEST
        {
            public IntPtr ProcessId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ModuleName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MODULE_RESPONSE
        {
            public IntPtr BaseAddress;
            public uint Size;
        }

        // ==================== P/INVOKE ====================

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        // ==================== FIELDS ====================

        private SafeFileHandle _driverHandle;

        // ==================== CONSTRUCTOR ====================

        public GuardLinkDriver()
        {
            _driverHandle = CreateFile(
                DEVICE_PATH,
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                0,
                IntPtr.Zero,
                3, // OPEN_EXISTING
                0,
                IntPtr.Zero);

            if (_driverHandle.IsInvalid)
            {
                throw new Exception($"Failed to open driver: {Marshal.GetLastWin32Error()}");
            }
        }

        // ==================== PUBLIC METHODS ====================

        public byte[] ReadMemory(int processId, IntPtr address, int size)
        {
            // Alocar buffer para request
            int requestSize = Marshal.SizeOf<MEMORY_OPERATION>() + size - 1;
            IntPtr requestPtr = Marshal.AllocHGlobal(requestSize);
            IntPtr responsePtr = Marshal.AllocHGlobal(requestSize);

            try
            {
                // Preparar request
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)size,
                    Buffer = new byte[1]
                };

                Marshal.StructureToPtr(request, requestPtr, false);

                // Chamar driver
                bool result = DeviceIoControl(
                    _driverHandle,
                    IOCTL_READ_MEMORY,
                    requestPtr,
                    (uint)requestSize,
                    responsePtr,
                    (uint)requestSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!result)
                {
                    throw new Exception($"ReadMemory failed: {Marshal.GetLastWin32Error()}");
                }

                // Extrair dados
                byte[] data = new byte[size];
                IntPtr bufferOffset = IntPtr.Add(responsePtr,
                    Marshal.OffsetOf<MEMORY_OPERATION>("Buffer").ToInt32());
                Marshal.Copy(bufferOffset, data, 0, size);

                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(requestPtr);
                Marshal.FreeHGlobal(responsePtr);
            }
        }

        public bool WriteMemory(int processId, IntPtr address, byte[] data)
        {
            int requestSize = Marshal.SizeOf<MEMORY_OPERATION>() + data.Length - 1;
            IntPtr requestPtr = Marshal.AllocHGlobal(requestSize);

            try
            {
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)data.Length,
                    Buffer = new byte[1]
                };

                Marshal.StructureToPtr(request, requestPtr, false);

                // Copiar dados
                IntPtr bufferOffset = IntPtr.Add(requestPtr,
                    Marshal.OffsetOf<MEMORY_OPERATION>("Buffer").ToInt32());
                Marshal.Copy(data, 0, bufferOffset, data.Length);

                bool result = DeviceIoControl(
                    _driverHandle,
                    IOCTL_WRITE_MEMORY,
                    requestPtr,
                    (uint)requestSize,
                    IntPtr.Zero,
                    0,
                    out _,
                    IntPtr.Zero);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(requestPtr);
            }
        }

        public IntPtr GetModuleBase(int processId, string moduleName)
        {
            var request = new MODULE_REQUEST
            {
                ProcessId = new IntPtr(processId),
                ModuleName = moduleName
            };

            IntPtr requestPtr = Marshal.AllocHGlobal(Marshal.SizeOf<MODULE_REQUEST>());
            IntPtr responsePtr = Marshal.AllocHGlobal(Marshal.SizeOf<MODULE_RESPONSE>());

            try
            {
                Marshal.StructureToPtr(request, requestPtr, false);

                bool result = DeviceIoControl(
                    _driverHandle,
                    IOCTL_GET_MODULE,
                    requestPtr,
                    (uint)Marshal.SizeOf<MODULE_REQUEST>(),
                    responsePtr,
                    (uint)Marshal.SizeOf<MODULE_RESPONSE>(),
                    out _,
                    IntPtr.Zero);

                if (!result) return IntPtr.Zero;

                var response = Marshal.PtrToStructure<MODULE_RESPONSE>(responsePtr);
                return response.BaseAddress;
            }
            finally
            {
                Marshal.FreeHGlobal(requestPtr);
                Marshal.FreeHGlobal(responsePtr);
            }
        }

        // ==================== HELPER METHODS ====================

        public T Read<T>(int processId, IntPtr address) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            byte[] data = ReadMemory(processId, address, size);

            IntPtr ptr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(data, 0, ptr, size);
                return Marshal.PtrToStructure<T>(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public bool Write<T>(int processId, IntPtr address, T value) where T : struct
        {
            int size = Marshal.SizeOf<T>();
            IntPtr ptr = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(value, ptr, false);
                byte[] data = new byte[size];
                Marshal.Copy(ptr, data, 0, size);

                return WriteMemory(processId, address, data);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public void Dispose()
        {
            _driverHandle?.Dispose();
        }
    }
}