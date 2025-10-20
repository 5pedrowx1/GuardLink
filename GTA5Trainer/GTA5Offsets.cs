using System;
using System.Linq;

namespace GTATrainer
{
    /// <summary>
    /// Offsets e Patterns para GTA V
    /// Suporta múltiplas versões através de Pattern Scanning
    /// </summary>
    public static class GTA5Offsets
    {
        // ==================== VERSÕES CONHECIDAS ====================
        public static class Version_1_66_2824
        {
            public const int WorldPtrOffset = 0x25F5BB0;
            public const int PlayerOffset = 0x08;
            public const int HealthOffset = 0x280;
            public const int MaxHealthOffset = 0x2A0;
            public const int ArmorOffset = 0x14B0;
            public const int VisualXOffset = 0x90;
            public const int VisualYOffset = 0x94;
            public const int VisualZOffset = 0x98;
            public const int PlayerInfoOffset = 0x10C8;
            public const int WantedLevelOffset = 0x888;
        }

        public static class Version_1_69_3258
        {
            public const int WorldPtrOffset = 0x2616BB0;
            public const int PlayerOffset = 0x08;
            public const int HealthOffset = 0x280;
            public const int MaxHealthOffset = 0x2A0;
            public const int ArmorOffset = 0x14B0;
            public const int VisualXOffset = 0x90;
            public const int VisualYOffset = 0x94;
            public const int VisualZOffset = 0x98;
            public const int PlayerInfoOffset = 0x10C8;
            public const int WantedLevelOffset = 0x888;
        }

        // ==================== OFFSETS DINÂMICOS (AUTO-DETECT) ====================
        public static int WorldPtrOffset { get; private set; }
        public static int PlayerOffset { get; private set; } = 0x08;
        public static int HealthOffset { get; private set; } = 0x280;
        public static int MaxHealthOffset { get; private set; } = 0x2A0;
        public static int ArmorOffset { get; private set; } = 0x14B0;
        public static int VisualXOffset { get; private set; } = 0x90;
        public static int VisualYOffset { get; private set; } = 0x94;
        public static int VisualZOffset { get; private set; } = 0x98;
        public static int PlayerInfoOffset { get; private set; } = 0x10C8;
        public static int WantedLevelOffset { get; private set; } = 0x888;

        // ==================== PATTERN SIGNATURES ====================
        // Esses patterns são usados para encontrar os offsets automaticamente
        private static readonly string WorldPattern = "48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9 74 07";
        private static readonly string HealthPattern = "F3 0F 10 8F ? ? ? ? F3 0F 11 0D";

        // ==================== INICIALIZAÇÃO ====================
        static GTA5Offsets()
        {
            // Por padrão, usa offsets da versão 1.66
            // Será atualizado quando FindOffsets() for chamado
            WorldPtrOffset = Version_1_66_2824.WorldPtrOffset;
        }

        /// <summary>
        /// Tenta encontrar os offsets automaticamente usando pattern scanning
        /// </summary>
        public static bool FindOffsets(GuardLinkDriver driver, int processId, IntPtr baseAddress)
        {
            try
            {
                Console.WriteLine("[*] Attempting to find offsets using pattern scanning...");

                // Tenta encontrar o World Pointer
                var worldOffset = FindPattern(driver, processId, baseAddress, WorldPattern, 0x10000000);
                if (worldOffset != -1)
                {
                    WorldPtrOffset = worldOffset;
                    Console.WriteLine($"[+] World pointer found: 0x{WorldPtrOffset:X}");
                    return true;
                }
                else
                {
                    Console.WriteLine("[!] Could not find World pointer pattern");
                    Console.WriteLine("[*] Falling back to default offsets for v1.66...");
                    return false;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Pattern scanning failed: {ex.Message}");
                Console.WriteLine("[*] Using default offsets for v1.66...");
                return false;
            }
        }

        /// <summary>
        /// Detecta automaticamente a versão do GTA V
        /// </summary>
        public static string DetectVersion(GuardLinkDriver driver, int processId, IntPtr baseAddress)
        {
            try
            {
                // Lê os primeiros bytes do executável para verificar a versão
                byte[] header = driver.ReadMemory(processId, baseAddress, 256);

                // Verifica assinaturas conhecidas
                // Isso é apenas um exemplo - você precisaria das assinaturas reais
                if (header.Length > 100)
                {
                    Console.WriteLine("[*] GTA V executable detected");
                    return "Unknown";
                }

                return "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Define manualmente a versão do GTA V
        /// </summary>
        public static void SetVersion(string version)
        {
            switch (version.ToLower())
            {
                case "1.66":
                case "2824":
                    WorldPtrOffset = Version_1_66_2824.WorldPtrOffset;
                    Console.WriteLine("[+] Using offsets for GTA V 1.66 Build 2824");
                    break;

                case "1.69":
                case "3258":
                    WorldPtrOffset = Version_1_69_3258.WorldPtrOffset;
                    Console.WriteLine("[+] Using offsets for GTA V 1.69 Build 3258");
                    break;

                default:
                    Console.WriteLine($"[!] Unknown version: {version}");
                    Console.WriteLine("[*] Using default offsets for v1.66...");
                    WorldPtrOffset = Version_1_66_2824.WorldPtrOffset;
                    break;
            }
        }

        /// <summary>
        /// Procura um pattern na memória
        /// </summary>
        private static int FindPattern(GuardLinkDriver driver, int processId, IntPtr baseAddress, string pattern, int searchSize)
        {
            try
            {
                // Converte o pattern string para bytes
                var patternBytes = ParsePattern(pattern, out byte[] mask);

                // Lê a memória em chunks
                const int chunkSize = 4096;
                for (int offset = 0; offset < searchSize; offset += chunkSize - patternBytes.Length)
                {
                    try
                    {
                        byte[] memory = driver.ReadMemory(processId, IntPtr.Add(baseAddress, offset), chunkSize);

                        // Procura o pattern
                        int index = FindPatternInBuffer(memory, patternBytes, mask);
                        if (index != -1)
                        {
                            return offset + index;
                        }
                    }
                    catch
                    {
                        // Ignora erros de leitura e continua
                        continue;
                    }
                }

                return -1;
            }
            catch
            {
                return -1;
            }
        }

        /// <summary>
        /// Converte pattern string (ex: "48 8B ? ?") em bytes e máscara
        /// </summary>
        private static byte[] ParsePattern(string pattern, out byte[] mask)
        {
            var parts = pattern.Split(' ');
            var bytes = new byte[parts.Length];
            mask = new byte[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == "?")
                {
                    bytes[i] = 0;
                    mask[i] = 0;
                }
                else
                {
                    bytes[i] = Convert.ToByte(parts[i], 16);
                    mask[i] = 1;
                }
            }

            return bytes;
        }

        /// <summary>
        /// Procura pattern em um buffer de memória
        /// </summary>
        private static int FindPatternInBuffer(byte[] buffer, byte[] pattern, byte[] mask)
        {
            for (int i = 0; i <= buffer.Length - pattern.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] == 1 && buffer[i + j] != pattern[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    return i;
                }
            }

            return -1;
        }
    }
}