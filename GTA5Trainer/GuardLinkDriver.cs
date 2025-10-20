using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GTATrainer
{
    public class GuardLinkDriver : IDisposable
    {
        private const string DEVICE_PATH = @"\\.\Global\GuardLink";

        private const uint IOCTL_SET_TARGET = 0x00222000;
        private const uint IOCTL_ENABLE_MONITOR = 0x00222004;
        private const uint IOCTL_READ_MEMORY = 0x00222008;
        private const uint IOCTL_WRITE_MEMORY = 0x0022200C;
        private const uint IOCTL_GET_MODULE = 0x00222010;
        private const uint IOCTL_INSTALL_HOOK = 0x00222014;
        private const uint IOCTL_REMOVE_HOOK = 0x00222018;
        private const uint IOCTL_HIDE_PROCESS = 0x0022201C;
        private const uint IOCTL_PROTECT_PROCESS = 0x00222020;

        // ==================== STRUCTURES (FIXED ALIGNMENT) ====================

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct MEMORY_OPERATION
        {
            public ulong ProcessId;
            public ulong Address;   
            public ulong Size;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4096)]
            public byte[] Buffer;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8, CharSet = CharSet.Unicode)]
        public struct MODULE_REQUEST
        {
            public ulong ProcessId;  
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string ModuleName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 8)]
        public struct MODULE_RESPONSE
        {
            public ulong BaseAddress;  
            public uint Size;
            public uint Padding;      
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

        private SafeFileHandle _driverHandle;
        private bool _disposed = false;

        public GuardLinkDriver()
        {
            Console.WriteLine("[*] Opening driver connection...");
            Console.WriteLine($"[*] Device path: {DEVICE_PATH}");

            _driverHandle = CreateFile(
                DEVICE_PATH,
                0xC0000000,
                0,
                IntPtr.Zero,
                3,
                0x80,
                IntPtr.Zero);

            if (_driverHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                string errorMsg = GetWin32ErrorMessage(error);
                throw new Exception($"Failed to open driver: Error {error} (0x{error:X}) - {errorMsg}");
            }

            Console.WriteLine("[+] Driver connection established");
        }

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
                    ProcessId = (ulong)processId,        
                    Address = (ulong)address.ToInt64(),
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
                    ProcessId = (ulong)processId,           
                    Address = (ulong)address.ToInt64(),     
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

            var request = new MODULE_REQUEST
            {
                ProcessId = (ulong)processId,  
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
                    return IntPtr.Zero;
                }

                var response = Marshal.PtrToStructure<MODULE_RESPONSE>(outBuffer);
                Console.WriteLine($"[+] Module base: 0x{response.BaseAddress:X16}, Size: 0x{response.Size:X}");

                return new IntPtr((long)response.BaseAddress);  
            }
            finally
            {
                Marshal.FreeHGlobal(inBuffer);
                Marshal.FreeHGlobal(outBuffer);
            }
        }

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
                1 => "ERROR_INVALID_FUNCTION",
                2 => "ERROR_FILE_NOT_FOUND",
                5 => "ERROR_ACCESS_DENIED",
                6 => "ERROR_INVALID_HANDLE",
                87 => "ERROR_INVALID_PARAMETER",
                995 => "ERROR_OPERATION_ABORTED",
                1784 => "ERROR_INVALID_OWNER",
                _ => $"Unknown error: {errorCode}"
            };
        }

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