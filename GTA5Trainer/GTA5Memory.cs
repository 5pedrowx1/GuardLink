using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace GTATrainer
{
    public class GTA5Memory
    {
        private GuardLinkDriver _driver;
        private Process _process;
        private IntPtr _baseAddress;

        // ==================== CONSTRUCTOR ====================

        public GTA5Memory()
        {
            if (!IsAdministrator())
            {
                throw new Exception("This program must run as Administrator!");
            }

            if (!IsDriverLoaded())
            {
                throw new Exception("GuardLink driver is not loaded!\nRun in Administrator command prompt:\n  sc start GuardLink");
            }

            _driver = new GuardLinkDriver();

            Process[] processes = Process.GetProcessesByName("GTA5");
            if (processes.Length == 0)
            {
                throw new Exception("GTA 5 not running!");
            }

            _process = processes[0];
            Console.WriteLine($"[+] GTA 5 found: PID={_process.Id}");

            _baseAddress = _driver.GetModuleBase(_process.Id, "GTA5.exe");
            if (_baseAddress == IntPtr.Zero)
            {
                throw new Exception("Failed to get GTA5.exe base address");
            }

            Console.WriteLine($"[+] GTA5.exe base: 0x{_baseAddress.ToInt64():X}");

            //Console.WriteLine("\n[*] Detecting GTA V version...");
            //string version = GTA5Offsets.DetectVersion(_driver, _process.Id, _baseAddress);
            //Console.WriteLine($"[*] Detected version: {version}");

            //Console.WriteLine("[+] Offsets loaded successfully");
        }

        // ==================== ADMIN CHECK ====================

        [DllImport("shell32.dll", SetLastError = true)]
        static extern bool IsUserAnAdmin();

        private static bool IsAdministrator()
        {
            try
            {
                return IsUserAnAdmin();
            }
            catch
            {
                return false;
            }
        }

        // ==================== DRIVER CHECK ====================

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        private static bool IsDriverLoaded()
        {
            try
            {
                Console.WriteLine("[*] Checking if driver device exists...");

                SafeFileHandle handle = CreateFile(
                    @"\\.\Global\GuardLink",
                    0x80000000, 
                    0,
                    IntPtr.Zero,
                    3, 
                    0,
                    IntPtr.Zero);

                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine($"[!] Driver device not found (Error {error})");
                    Console.WriteLine("[!] Make sure the driver is loaded:");
                    Console.WriteLine("    sc query GuardLink");
                    Console.WriteLine("    sc start GuardLink");
                    return false;
                }

                handle.Dispose();
                Console.WriteLine("[+] Driver device found and accessible");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Cannot check driver status: {ex.Message}");
                return false;
            }
        }

        // ==================== HELPER METHODS ====================

        private IntPtr GetPlayerPointer()
        {
            IntPtr worldPtr = _driver.Read<IntPtr>(_process.Id,
                IntPtr.Add(_baseAddress, GTA5Offsets.WorldPtrOffset));

            if (worldPtr == IntPtr.Zero) return IntPtr.Zero;

            IntPtr playerPtr = _driver.Read<IntPtr>(_process.Id,
                IntPtr.Add(worldPtr, GTA5Offsets.PlayerOffset));

            return playerPtr;
        }

        // ==================== PUBLIC METHODS ====================

        public float GetHealth()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<float>(_process.Id,
                IntPtr.Add(player, GTA5Offsets.HealthOffset));
        }

        public void SetHealth(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, GTA5Offsets.HealthOffset), value);
        }

        public void SetMaxHealth(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, GTA5Offsets.MaxHealthOffset), value);
        }

        public float GetArmor()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<float>(_process.Id,
                IntPtr.Add(player, GTA5Offsets.ArmorOffset));
        }

        public void SetArmor(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, GTA5Offsets.ArmorOffset), value);
        }

        public int GetWantedLevel()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<int>(_process.Id,
                IntPtr.Add(player, GTA5Offsets.WantedLevelOffset));
        }

        public void SetWantedLevel(int value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, GTA5Offsets.WantedLevelOffset), value);
        }

        public (float x, float y, float z) GetPosition()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return (0, 0, 0);

            float x = _driver.Read<float>(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualXOffset));
            float y = _driver.Read<float>(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualYOffset));
            float z = _driver.Read<float>(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualZOffset));

            return (x, y, z);
        }

        public void Teleport(float x, float y, float z)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualXOffset), x);
            _driver.Write(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualYOffset), y);
            _driver.Write(_process.Id, IntPtr.Add(player, GTA5Offsets.VisualZOffset), z);
        }

        public void EnableGodMode(bool enable)
        {
            if (enable)
            {
                SetHealth(9999.0f);
                SetMaxHealth(9999.0f);
                SetArmor(9999.0f);
            }
            else
            {
                SetMaxHealth(328.0f);
                SetHealth(328.0f);
                SetArmor(0.0f);
            }
        }
    }
}