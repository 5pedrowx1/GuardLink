using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GTATrainer
{
    public class GuardLinkDriver : IDisposable
    {
        // ==================== CONSTANTS ====================

        private const string DEVICE_PATH = @"\\.\Global\GuardLink";

        // ⚠️ IOCTL codes MUST match the driver's CTL_CODE macro
        // Formula: ((DeviceType << 16) | (Access << 14) | (Function << 2) | Method)
        // FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0

        private const uint IOCTL_SET_TARGET = 0x00222000; // 0x800 << 2
        private const uint IOCTL_ENABLE_MONITOR = 0x00222004; // 0x801 << 2
        private const uint IOCTL_READ_MEMORY = 0x00222008; // 0x802 << 2
        private const uint IOCTL_WRITE_MEMORY = 0x0022200C; // 0x803 << 2
        private const uint IOCTL_GET_MODULE = 0x00222010; // 0x804 << 2
        private const uint IOCTL_INSTALL_HOOK = 0x00222014; // 0x805 << 2
        private const uint IOCTL_REMOVE_HOOK = 0x00222018; // 0x806 << 2
        private const uint IOCTL_HIDE_PROCESS = 0x0022201C; // 0x807 << 2
        private const uint IOCTL_PROTECT_PROCESS = 0x00222020; // 0x808 << 2

        // ==================== STRUCTURES ====================

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MEMORY_OPERATION
        {
            public IntPtr ProcessId;
            public IntPtr Address;
            public ulong Size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
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
        private bool _disposed = false;

        // ==================== CONSTRUCTOR ====================

        public GuardLinkDriver()
        {
            Console.WriteLine("[*] Opening driver connection...");
            Console.WriteLine($"[*] Device path: {DEVICE_PATH}");

            _driverHandle = CreateFile(
                DEVICE_PATH,
                0xC0000000, // GENERIC_READ | GENERIC_WRITE
                0,          // No sharing
                IntPtr.Zero,
                3,          // OPEN_EXISTING
                0x80,       // FILE_ATTRIBUTE_NORMAL
                IntPtr.Zero);

            if (_driverHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMsg = GetWin32ErrorMessage(error);
                throw new Exception($"Failed to open driver: Error {error} (0x{error:X}) - {errorMsg}");
            }

            Console.WriteLine("[+] Driver connection established");
        }

        // ==================== PUBLIC METHODS ====================

        public byte[] ReadMemory(int processId, IntPtr address, int size)
        {
            if (size <= 0 || size > 4096)
                throw new ArgumentException("Size must be between 1 and 4096 bytes");

            int structSize = Marshal.SizeOf<MEMORY_OPERATION>();

            IntPtr inBuffer = Marshal.AllocHGlobal(structSize);
            IntPtr outBuffer = Marshal.AllocHGlobal(structSize);

            try
            {
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)size,
                    Buffer = new byte[4096]
                };

                Marshal.StructureToPtr(request, inBuffer, false);

                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_READ_MEMORY,
                    inBuffer,
                    (uint)structSize,
                    outBuffer,
                    (uint)structSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Exception($"ReadMemory failed: Error {error} (0x{error:X}) - {GetWin32ErrorMessage(error)}");
                }

                var response = Marshal.PtrToStructure<MEMORY_OPERATION>(outBuffer);

                byte[] result = new byte[size];
                Array.Copy(response.Buffer, result, size);

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(inBuffer);
                Marshal.FreeHGlobal(outBuffer);
            }
        }

        public bool WriteMemory(int processId, IntPtr address, byte[] data)
        {
            if (data == null || data.Length == 0 || data.Length > 4096)
                throw new ArgumentException("Data must be between 1 and 4096 bytes");

            int structSize = Marshal.SizeOf<MEMORY_OPERATION>();
            IntPtr inBuffer = Marshal.AllocHGlobal(structSize);

            try
            {
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)data.Length,
                    Buffer = new byte[4096]
                };

                Array.Copy(data, request.Buffer, data.Length);
                Marshal.StructureToPtr(request, inBuffer, false);

                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_WRITE_MEMORY,
                    inBuffer,
                    (uint)structSize,
                    IntPtr.Zero,
                    0,
                    out _,
                    IntPtr.Zero);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[-] WriteMemory failed: Error {error} (0x{error:X}) - {GetWin32ErrorMessage(error)}");
                    return false;
                }

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(inBuffer);
            }
        }

        public IntPtr GetModuleBase(int processId, string moduleName)
        {
            Console.WriteLine($"[*] GetModuleBase: PID={processId}, Module={moduleName}");
            Console.WriteLine($"[*] Using IOCTL: 0x{IOCTL_GET_MODULE:X8}");

            var request = new MODULE_REQUEST
            {
                ProcessId = new IntPtr(processId),
                ModuleName = moduleName
            };

            int inSize = Marshal.SizeOf<MODULE_REQUEST>();
            int outSize = Marshal.SizeOf<MODULE_RESPONSE>();

            IntPtr inBuffer = Marshal.AllocHGlobal(inSize);
            IntPtr outBuffer = Marshal.AllocHGlobal(outSize);

            try
            {
                Marshal.StructureToPtr(request, inBuffer, false);

                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_GET_MODULE,
                    inBuffer,
                    (uint)inSize,
                    outBuffer,
                    (uint)outSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    string errorMsg = GetWin32ErrorMessage(error);
                    Console.WriteLine($"[-] GetModuleBase failed: Error {error} (0x{error:X}) - {errorMsg}");
                    Console.WriteLine($"[-] Bytes returned: {bytesReturned}");
                    return IntPtr.Zero;
                }

                var response = Marshal.PtrToStructure<MODULE_RESPONSE>(outBuffer);
                Console.WriteLine($"[+] Module base: 0x{response.BaseAddress.ToInt64():X16}, Size: 0x{response.Size:X}");

                return response.BaseAddress;
            }
            finally
            {
                Marshal.FreeHGlobal(inBuffer);
                Marshal.FreeHGlobal(outBuffer);
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

        private string GetWin32ErrorMessage(int errorCode)
        {
            return errorCode switch
            {
                1 => "ERROR_INVALID_FUNCTION - The IOCTL code doesn't match",
                2 => "ERROR_FILE_NOT_FOUND - Driver device not found",
                5 => "ERROR_ACCESS_DENIED - Insufficient privileges",
                6 => "ERROR_INVALID_HANDLE - Invalid driver handle",
                87 => "ERROR_INVALID_PARAMETER - Invalid buffer or parameters",
                995 => "ERROR_OPERATION_ABORTED - Operation canceled",
                1784 => "ERROR_INVALID_OWNER - Security context issue",
                _ => $"Unknown error code: {errorCode}"
            };
        }

        // ==================== DISPOSABLE PATTERN ====================

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _driverHandle?.Dispose();
                }
                _disposed = true;
            }
        }

        ~GuardLinkDriver()
        {
            Dispose(false);
        }
    }
}