using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GTATrainer
{
    public class GuardLinkDriver : IDisposable
    {
        // ==================== CONSTANTS ====================

        private const string DEVICE_PATH = @"\\.\Global\GuardLink";

        private const uint IOCTL_SET_TARGET = 0x22002000;
        private const uint IOCTL_ENABLE_MONITOR = 0x22002004;
        private const uint IOCTL_READ_MEMORY = 0x22002008;
        private const uint IOCTL_WRITE_MEMORY = 0x2200200C;
        private const uint IOCTL_GET_MODULE = 0x22002010;
        private const uint IOCTL_INSTALL_HOOK = 0x22002014;
        private const uint IOCTL_REMOVE_HOOK = 0x22002018;
        private const uint IOCTL_HIDE_PROCESS = 0x2200201C;
        private const uint IOCTL_PROTECT_PROCESS = 0x22002020;

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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

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

            // Calcular tamanho total da estrutura
            int structSize = Marshal.SizeOf<MEMORY_OPERATION>();
            int totalSize = structSize + size - 4096; // Subtrair o tamanho do buffer padrão

            IntPtr inBuffer = Marshal.AllocHGlobal(totalSize);
            IntPtr outBuffer = Marshal.AllocHGlobal(totalSize);

            try
            {
                // Preparar estrutura de input
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)size,
                    Buffer = new byte[4096] // Buffer temporário
                };

                Marshal.StructureToPtr(request, inBuffer, false);

                // Chamar driver
                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_READ_MEMORY,
                    inBuffer,
                    (uint)totalSize,
                    outBuffer,
                    (uint)totalSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    throw new Exception($"ReadMemory failed: Error {error} (0x{error:X}) - {GetWin32ErrorMessage(error)}");
                }

                // Extrair dados do output
                var response = Marshal.PtrToStructure<MEMORY_OPERATION>(outBuffer);

                // Copiar apenas os bytes necessários
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
            int totalSize = structSize + data.Length - 4096;

            IntPtr inBuffer = Marshal.AllocHGlobal(totalSize);

            try
            {
                var request = new MEMORY_OPERATION
                {
                    ProcessId = new IntPtr(processId),
                    Address = address,
                    Size = (ulong)data.Length,
                    Buffer = new byte[4096]
                };

                // Copiar dados para o buffer
                Array.Copy(data, request.Buffer, data.Length);

                Marshal.StructureToPtr(request, inBuffer, false);

                bool success = DeviceIoControl(
                    _driverHandle,
                    IOCTL_WRITE_MEMORY,
                    inBuffer,
                    (uint)totalSize,
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
                ProcessId = new IntPtr(processId),
                ModuleName = moduleName
            };

            var response = new MODULE_RESPONSE();

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

                response = Marshal.PtrToStructure<MODULE_RESPONSE>(outBuffer);
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
                1 => "ERROR_INVALID_FUNCTION",
                2 => "ERROR_FILE_NOT_FOUND",
                5 => "ERROR_ACCESS_DENIED",
                6 => "ERROR_INVALID_HANDLE",
                87 => "ERROR_INVALID_PARAMETER",
                995 => "ERROR_OPERATION_ABORTED",
                1784 => "ERROR_INVALID_OWNER",
                _ => "Unknown error"
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