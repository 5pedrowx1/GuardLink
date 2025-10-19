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

        // ==================== OFFSETS (GTA V 1.69) ====================
        // Nota: Estes offsets mudam a cada atualização!

        private const int OFFSET_WORLD = 0x2504BA0;
        private const int OFFSET_PLAYER = 0x08;
        private const int OFFSET_HEALTH = 0x280;
        private const int OFFSET_MAX_HEALTH = 0x2A0;
        private const int OFFSET_ARMOR = 0x14B0;
        private const int OFFSET_WANTED_LEVEL = 0x10C8;
        private const int OFFSET_MONEY = 0x1000;

        private const int OFFSET_POS_X = 0x90;
        private const int OFFSET_POS_Y = 0x94;
        private const int OFFSET_POS_Z = 0x98;

        // ==================== CONSTRUCTOR ====================

        public GTA5Memory()
        {
            // Verificar se está rodando como administrador
            if (!IsAdministrator())
            {
                throw new Exception("This program must run as Administrator!");
            }

            // Verificar se o driver está carregado
            if (!IsDriverLoaded())
            {
                throw new Exception("GuardLink driver is not loaded!\nRun in Administrator command prompt:\n  sc start GuardLink");
            }

            _driver = new GuardLinkDriver();

            // Encontrar processo do GTA
            Process[] processes = Process.GetProcessesByName("GTA5");
            if (processes.Length == 0)
            {
                throw new Exception("GTA 5 not running!");
            }

            _process = processes[0];
            Console.WriteLine($"[+] GTA 5 found: PID={_process.Id}");

            // Obter base do executável
            _baseAddress = _driver.GetModuleBase(_process.Id, "GTA5.exe");
            if (_baseAddress == IntPtr.Zero)
            {
                throw new Exception("Failed to get GTA5.exe base address");
            }

            Console.WriteLine($"[+] GTA5.exe base: 0x{_baseAddress.ToInt64():X}");
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

                // Tentar abrir o dispositivo
                SafeFileHandle handle = CreateFile(
                    @"\\.\Global\GuardLink",
                    0x80000000, // GENERIC_READ
                    0,
                    IntPtr.Zero,
                    3, // OPEN_EXISTING
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
                IntPtr.Add(_baseAddress, OFFSET_WORLD));

            if (worldPtr == IntPtr.Zero) return IntPtr.Zero;

            IntPtr playerPtr = _driver.Read<IntPtr>(_process.Id,
                IntPtr.Add(worldPtr, OFFSET_PLAYER));

            return playerPtr;
        }

        // ==================== PUBLIC METHODS ====================

        public float GetHealth()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<float>(_process.Id,
                IntPtr.Add(player, OFFSET_HEALTH));
        }

        public void SetHealth(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, OFFSET_HEALTH), value);
        }

        public void SetMaxHealth(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, OFFSET_MAX_HEALTH), value);
        }

        public float GetArmor()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<float>(_process.Id,
                IntPtr.Add(player, OFFSET_ARMOR));
        }

        public void SetArmor(float value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, OFFSET_ARMOR), value);
        }

        public int GetWantedLevel()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return 0;

            return _driver.Read<int>(_process.Id,
                IntPtr.Add(player, OFFSET_WANTED_LEVEL));
        }

        public void SetWantedLevel(int value)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id,
                IntPtr.Add(player, OFFSET_WANTED_LEVEL), value);
        }

        public (float x, float y, float z) GetPosition()
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return (0, 0, 0);

            float x = _driver.Read<float>(_process.Id, IntPtr.Add(player, OFFSET_POS_X));
            float y = _driver.Read<float>(_process.Id, IntPtr.Add(player, OFFSET_POS_Y));
            float z = _driver.Read<float>(_process.Id, IntPtr.Add(player, OFFSET_POS_Z));

            return (x, y, z);
        }

        public void Teleport(float x, float y, float z)
        {
            IntPtr player = GetPlayerPointer();
            if (player == IntPtr.Zero) return;

            _driver.Write(_process.Id, IntPtr.Add(player, OFFSET_POS_X), x);
            _driver.Write(_process.Id, IntPtr.Add(player, OFFSET_POS_Y), y);
            _driver.Write(_process.Id, IntPtr.Add(player, OFFSET_POS_Z), z);
        }

        // Godmode (congela vida em valor alto)
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