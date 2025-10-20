using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace GTAOffsetFinder
{
    class Program
    {
        static GuardLinkDriver driver;
        static Process gtaProcess;
        static IntPtr baseAddress;
        static PatternScanner scanner;

        static void Main(string[] args)
        {
            Console.Title = "GTA V Offset Finder - Powered by GuardLink";
            Console.ForegroundColor = ConsoleColor.Green;

            Console.WriteLine("╔════════════════════════════════════════════════╗");
            Console.WriteLine("║     GTA V OFFSET FINDER & SCANNER v2.0        ║");
            Console.WriteLine("║          Advanced Pattern Scanner             ║");
            Console.WriteLine("╚════════════════════════════════════════════════╝\n");
            Console.ResetColor();

            try
            {
                Initialize();

                bool running = true;
                while (running)
                {
                    PrintMenu();
                    var key = Console.ReadKey(true);
                    Console.WriteLine();

                    switch (key.Key)
                    {
                        case ConsoleKey.D1:
                            ScanAllOffsets();
                            break;

                        case ConsoleKey.D2:
                            ScanEssentialPatterns();
                            break;

                        case ConsoleKey.D3:
                            ScanNetworkPatterns();
                            break;

                        case ConsoleKey.D4:
                            ScanScriptPatterns();
                            break;

                        case ConsoleKey.D5:
                            ScanCustomPattern();
                            break;

                        case ConsoleKey.D6:
                            TestOffsets();
                            break;

                        case ConsoleKey.D7:
                            ExportResults();
                            break;

                        case ConsoleKey.D8:
                            ShowGameInfo();
                            break;

                        case ConsoleKey.D9:
                            running = false;
                            break;

                        default:
                            Console.WriteLine("[-] Invalid option");
                            break;
                    }

                    if (running)
                    {
                        Console.WriteLine("\nPress any key to continue...");
                        Console.ReadKey();
                        Console.Clear();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[-] Fatal Error: {ex.Message}");
                Console.WriteLine($"[-] Stack: {ex.StackTrace}");
                Console.ResetColor();
            }

            Console.WriteLine("\n[*] Closing...");
            driver?.Dispose();
        }

        static void PrintMenu()
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n╔════════════════════ MENU ════════════════════════╗");
            Console.ResetColor();
            Console.WriteLine("  1 - Scan ALL Patterns (Complete Scan)");
            Console.WriteLine("  2 - Scan Essential Patterns (Quick)");
            Console.WriteLine("  3 - Scan Network Patterns");
            Console.WriteLine("  4 - Scan Script Patterns");
            Console.WriteLine("  5 - Scan Custom Pattern");
            Console.WriteLine("  6 - Test Current Offsets");
            Console.WriteLine("  7 - Export Results to File");
            Console.WriteLine("  8 - Show Game Information");
            Console.WriteLine("  9 - Exit");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("╚══════════════════════════════════════════════════╝");
            Console.ResetColor();
            Console.Write("\nSelect option: ");
        }

        static void Initialize()
        {
            Console.WriteLine("[*] Initializing Pattern Scanner...\n");

            if (!IsAdministrator())
            {
                throw new Exception("This program MUST run as Administrator!");
            }
            Console.WriteLine("[+] Running as Administrator");

            driver = new GuardLinkDriver();
            Console.WriteLine("[+] Driver connection established");

            Process[] processes = Process.GetProcessesByName("GTA5");
            if (processes.Length == 0)
            {
                throw new Exception("GTA V is not running! Please start the game first.");
            }

            gtaProcess = processes[0];
            Console.WriteLine($"[+] GTA V found: PID={gtaProcess.Id}");

            baseAddress = driver.GetModuleBase(gtaProcess.Id, "GTA5.exe");
            if (baseAddress == IntPtr.Zero)
            {
                throw new Exception("Failed to get GTA5.exe base address");
            }

            Console.WriteLine($"[+] GTA5.exe base: 0x{baseAddress.ToInt64():X}");
            Console.WriteLine($"[+] Module size: ~{GetModuleSize()} MB");

            // Inicializar pattern scanner
            scanner = new PatternScanner(driver, gtaProcess)
            {
                UseCache = true,
                VerboseLogging = false
            };
            Console.WriteLine("[+] Pattern Scanner initialized");
        }

        static void ScanAllOffsets()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[*] Starting COMPLETE PATTERN SCAN...");
            Console.WriteLine("[*] This will scan ALL known patterns");
            Console.WriteLine("[*] This may take 2-5 minutes...\n");
            Console.ResetColor();

            var allPatterns = GTAPatterns.GetAllPatterns();
            var results = scanner.BatchScan(allPatterns);

            DisplayResults(results, "COMPLETE SCAN RESULTS");
        }

        static void ScanEssentialPatterns()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[*] Scanning ESSENTIAL patterns...");
            Console.WriteLine("[*] World, Player, Vehicle, Network");
            Console.ResetColor();

            var patterns = GTAPatterns.GetEssentialPatterns();
            var results = scanner.BatchScan(patterns);

            DisplayResults(results, "ESSENTIAL PATTERNS");
        }

        static void ScanNetworkPatterns()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[*] Scanning NETWORK patterns...");
            Console.ResetColor();

            var patterns = GTAPatterns.GetNetworkPatterns();
            var results = scanner.BatchScan(patterns);

            DisplayResults(results, "NETWORK PATTERNS");
        }

        static void ScanScriptPatterns()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[*] Scanning SCRIPT patterns...");
            Console.ResetColor();

            var patterns = GTAPatterns.GetScriptPatterns();
            var results = scanner.BatchScan(patterns);

            DisplayResults(results, "SCRIPT PATTERNS");
        }

        static void ScanCustomPattern()
        {
            Console.WriteLine("\n[*] Custom Pattern Scanner");
            Console.WriteLine("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

            Console.Write("Pattern Name: ");
            string name = Console.ReadLine();

            Console.Write("Pattern (e.g., 48 8B 05 ? ? ? ? 45): ");
            string signature = Console.ReadLine();

            Console.WriteLine("\nOffset Type:");
            Console.WriteLine("  1 - Absolute (direct offset)");
            Console.WriteLine("  2 - Relative (RIP-relative)");
            Console.WriteLine("  3 - Pointer");
            Console.Write("Select: ");

            OffsetType type = OffsetType.Absolute;
            var key = Console.ReadKey();
            Console.WriteLine();

            switch (key.KeyChar)
            {
                case '1': type = OffsetType.Absolute; break;
                case '2': type = OffsetType.RelativeOffset; break;
                case '3': type = OffsetType.Pointer; break;
            }

            Console.WriteLine("\n[*] Scanning...");

            var pattern = Pattern.Create(name, signature, type);
            var result = scanner.Scan(pattern);

            Console.WriteLine("\n" + new string('═', 60));
            if (result.Found)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] FOUND: {result.PatternName}");
                Console.ResetColor();
                Console.WriteLine($"    Pattern Offset:  0x{result.PatternOffset:X}");
                Console.WriteLine($"    Final Offset:    0x{result.FinalOffset:X}");
                Console.WriteLine($"    Address:         0x{result.Address.ToInt64():X}");
                Console.WriteLine($"    Valid:           {result.IsValid}");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] NOT FOUND: {result.PatternName}");
                Console.ResetColor();
            }
            Console.WriteLine(new string('═', 60));
        }

        static void DisplayResults(System.Collections.Generic.Dictionary<string, ScanResult> results, string title)
        {
            Console.WriteLine("\n\n");
            Console.WriteLine("╔" + new string('═', 58) + "╗");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"║  {title.PadRight(56)}║");
            Console.ResetColor();
            Console.WriteLine("╚" + new string('═', 58) + "╝\n");

            int foundCount = 0;
            int validCount = 0;

            foreach (var kvp in results.OrderBy(x => x.Key))
            {
                var result = kvp.Value;

                if (result.Found)
                {
                    foundCount++;
                    if (result.IsValid) validCount++;

                    Console.ForegroundColor = result.IsValid ? ConsoleColor.Green : ConsoleColor.Yellow;
                    string status = result.IsValid ? "✓" : "?";
                    Console.WriteLine($"{status} {result.PatternName.PadRight(25)} 0x{result.FinalOffset:X8}");
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"✗ {result.PatternName.PadRight(25)} NOT FOUND");
                    Console.ResetColor();
                }
            }

            Console.WriteLine("\n" + new string('─', 60));
            Console.WriteLine($"Found:    {foundCount}/{results.Count}");
            Console.WriteLine($"Validated: {validCount}/{foundCount}");

            if (validCount >= foundCount * 0.8)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Status: EXCELLENT ✓");
            }
            else if (validCount >= foundCount * 0.5)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Status: PARTIAL !");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Status: FAILED ✗");
            }
            Console.ResetColor();
        }

        static void TestOffsets()
        {
            Console.WriteLine("\n[*] Testing current offsets...\n");

            try
            {
                // Tentar obter World
                var worldPattern = Pattern.Create("World", "48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9", OffsetType.RelativeOffset);
                var worldResult = scanner.Scan(worldPattern);

                if (!worldResult.Found)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[-] Cannot test: World Pointer not found!");
                    Console.ResetColor();
                    return;
                }

                IntPtr worldPtr = driver.Read<IntPtr>(gtaProcess.Id, worldResult.Address);
                IntPtr playerPtr = driver.Read<IntPtr>(gtaProcess.Id, IntPtr.Add(worldPtr, 0x08));

                Console.WriteLine($"World Address:  0x{worldResult.Address.ToInt64():X}");
                Console.WriteLine($"World Pointer:  0x{worldPtr.ToInt64():X}");
                Console.WriteLine($"Player Pointer: 0x{playerPtr.ToInt64():X}\n");

                // Ler dados do player
                float health = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x280));
                float maxHealth = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x2A0));
                float armor = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x14B0));
                float x = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x90));
                float y = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x94));
                float z = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x98));

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("═══════════════════════════════════════════");
                Console.WriteLine("         CURRENT PLAYER DATA");
                Console.WriteLine("═══════════════════════════════════════════");
                Console.ResetColor();

                Console.WriteLine($"Health:     {health:F1} / {maxHealth:F1}");
                Console.WriteLine($"Armor:      {armor:F1}");
                Console.WriteLine($"Position:");
                Console.WriteLine($"  X: {x:F2}");
                Console.WriteLine($"  Y: {y:F2}");
                Console.WriteLine($"  Z: {z:F2}");

                // Tentar ler velocidade
                float speed = driver.Read<float>(gtaProcess.Id, IntPtr.Add(playerPtr, 0x300));
                Console.WriteLine($"Speed:      {speed:F2}");

                Console.WriteLine("═══════════════════════════════════════════");

                // Validação
                Console.WriteLine("\n[*] Validation:");
                Console.WriteLine($"  Health:   {(health > 0 && health <= maxHealth ? "✓ VALID" : "✗ INVALID")}");
                Console.WriteLine($"  Armor:    {(armor >= 0 && armor <= 100 ? "✓ VALID" : "✗ INVALID")}");
                Console.WriteLine($"  Position: {(Math.Abs(x) < 10000 && Math.Abs(y) < 10000 ? "✓ VALID" : "✗ INVALID")}");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Error: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void ExportResults()
        {
            Console.WriteLine("\n[*] Exporting results...\n");

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string filename = $"GTA5_Patterns_{timestamp}.txt";

            try
            {
                scanner.ExportCache(filename);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] Results exported to: {filename}");
                Console.ResetColor();

                // Também gerar arquivo C# com as definições
                string csFilename = $"GTA5_Offsets_{timestamp}.cs";
                GenerateCSharpFile(csFilename);

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"[+] C# definitions saved to: {csFilename}");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Export failed: {ex.Message}");
                Console.ResetColor();
            }
        }

        static void GenerateCSharpFile(string filename)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// ==================== GTA V OFFSETS ====================");
            sb.AppendLine($"// Generated: {DateTime.Now}");
            sb.AppendLine($"// Process: {gtaProcess.ProcessName} (PID: {gtaProcess.Id})");
            sb.AppendLine($"// Base Address: 0x{baseAddress.ToInt64():X}");
            sb.AppendLine($"// Game Version: {GetGameVersion()}");
            sb.AppendLine();
            sb.AppendLine("using System;");
            sb.AppendLine();
            sb.AppendLine("namespace GTA5Offsets");
            sb.AppendLine("{");
            sb.AppendLine("    public static class Offsets");
            sb.AppendLine("    {");
            sb.AppendLine("        // Base Address");
            sb.AppendLine($"        public static readonly IntPtr BaseAddress = new IntPtr(0x{baseAddress.ToInt64():X});");
            sb.AppendLine();

            // Adicionar offsets do cache
            sb.AppendLine("        // Pattern Offsets");
            var allPatterns = GTAPatterns.GetAllPatterns();
            var results = scanner.BatchScan(allPatterns);

            foreach (var kvp in results.OrderBy(x => x.Key))
            {
                if (kvp.Value.Found)
                {
                    string varName = kvp.Key.Replace(" ", "").Replace("-", "");
                    sb.AppendLine($"        public const int {varName} = 0x{kvp.Value.FinalOffset:X}; // {(kvp.Value.IsValid ? "Validated" : "Unvalidated")}");
                }
            }

            sb.AppendLine();
            sb.AppendLine("        // Player Structure Offsets");
            sb.AppendLine("        public const int PlayerHealth = 0x280;");
            sb.AppendLine("        public const int PlayerMaxHealth = 0x2A0;");
            sb.AppendLine("        public const int PlayerArmor = 0x14B0;");
            sb.AppendLine("        public const int PlayerVisualX = 0x90;");
            sb.AppendLine("        public const int PlayerVisualY = 0x94;");
            sb.AppendLine("        public const int PlayerVisualZ = 0x98;");
            sb.AppendLine("        public const int PlayerSpeed = 0x300;");
            sb.AppendLine("        public const int PlayerWantedLevel = 0x888;");
            sb.AppendLine("    }");
            sb.AppendLine("}");

            File.WriteAllText(filename, sb.ToString());
        }

        static void ShowGameInfo()
        {
            Console.WriteLine("\n[*] GTA V Game Information:\n");
            Console.WriteLine($"Process Name:     {gtaProcess.ProcessName}");
            Console.WriteLine($"Process ID:       {gtaProcess.Id}");
            Console.WriteLine($"Base Address:     0x{baseAddress.ToInt64():X}");
            Console.WriteLine($"Memory Usage:     {gtaProcess.WorkingSet64 / 1024 / 1024} MB");
            Console.WriteLine($"Module Size:      {GetModuleSize()} MB");
            Console.WriteLine($"Handle Count:     {gtaProcess.HandleCount}");
            Console.WriteLine($"Thread Count:     {gtaProcess.Threads.Count}");

            try
            {
                var versionInfo = gtaProcess.MainModule.FileVersionInfo;
                Console.WriteLine($"\nFile Version:     {versionInfo.FileVersion}");
                Console.WriteLine($"Product Version:  {versionInfo.ProductVersion}");
                Console.WriteLine($"File Description: {versionInfo.FileDescription}");
            }
            catch { }

            Console.WriteLine($"\nPattern Scanner:");
            Console.WriteLine($"  Chunk Size:       {scanner.ChunkSize / 1024} KB");
            Console.WriteLine($"  Cache Enabled:    {scanner.UseCache}");
            Console.WriteLine($"  Verbose Logging:  {scanner.VerboseLogging}");
        }

        static string GetGameVersion()
        {
            try
            {
                var versionInfo = gtaProcess.MainModule.FileVersionInfo;
                return versionInfo.FileVersion ?? "Unknown";
            }
            catch
            {
                return "Unknown";
            }
        }

        static long GetModuleSize()
        {
            try
            {
                return gtaProcess.MainModule.ModuleMemorySize / 1024 / 1024;
            }
            catch
            {
                return 0;
            }
        }

        [DllImport("shell32.dll")]
        static extern bool IsUserAnAdmin();

        static bool IsAdministrator()
        {
            try { return IsUserAnAdmin(); }
            catch { return false; }
        }
    }
}