using System;
using System.Threading;

namespace GTATrainer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Title = "GTA V Trainer - Powered by GuardLink";
            Console.ForegroundColor = ConsoleColor.Cyan;

            Console.WriteLine("========================================");
            Console.WriteLine("      GTA V Offline Trainer v1.0       ");
            Console.WriteLine("       Using Kernel Driver Access       ");
            Console.WriteLine("========================================\n");
            Console.ResetColor();

            try
            {
                var gta = new GTA5Memory();
                bool running = true;

                Console.WriteLine("[+] Trainer loaded successfully!\n");

                while (running)
                {
                    PrintMenu();

                    var key = Console.ReadKey(true);
                    Console.WriteLine();

                    switch (key.Key)
                    {
                        case ConsoleKey.NumPad1:
                            Console.WriteLine("[*] Setting God Mode...");
                            gta.EnableGodMode(true);
                            Console.WriteLine("[+] God Mode Enabled!");
                            break;

                        case ConsoleKey.NumPad2:
                            Console.WriteLine("[*] Disabling God Mode...");
                            gta.EnableGodMode(false);
                            Console.WriteLine("[+] God Mode Disabled!");
                            break;

                        case ConsoleKey.NumPad3:
                            Console.WriteLine("[*] Clearing wanted level...");
                            gta.SetWantedLevel(0);
                            Console.WriteLine("[+] Wanted level cleared!");
                            break;

                        case ConsoleKey.NumPad4:
                            Console.WriteLine("[*] Refilling health & armor...");
                            gta.SetHealth(328.0f);
                            gta.SetArmor(100.0f);
                            Console.WriteLine("[+] Health & Armor refilled!");
                            break;

                        case ConsoleKey.NumPad5:
                            var pos = gta.GetPosition();
                            Console.WriteLine($"[*] Current Position:");
                            Console.WriteLine($"    X: {pos.x:F2}");
                            Console.WriteLine($"    Y: {pos.y:F2}");
                            Console.WriteLine($"    Z: {pos.z:F2}");
                            break;

                        case ConsoleKey.NumPad6:
                            Console.WriteLine("[*] Teleporting to airport...");
                            gta.Teleport(-1336.0f, -3044.0f, 14.0f);
                            Console.WriteLine("[+] Teleported!");
                            break;

                        case ConsoleKey.NumPad0:
                            running = false;
                            break;

                        default:
                            Console.WriteLine("[-] Invalid option");
                            break;
                    }

                    Thread.Sleep(100);
                }

                Console.WriteLine("\n[*] Trainer closed.");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[-] Error: {ex.Message}");
                Console.ResetColor();
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        static void PrintMenu()
        {
            Console.WriteLine("\n========= MENU =========");
            Console.WriteLine("NumPad1 - God Mode ON");
            Console.WriteLine("NumPad2 - God Mode OFF");
            Console.WriteLine("NumPad3 - Clear Wanted");
            Console.WriteLine("NumPad4 - Refill HP/Armor");
            Console.WriteLine("NumPad5 - Show Position");
            Console.WriteLine("NumPad6 - TP to Airport");
            Console.WriteLine("NumPad0 - Exit");
            Console.WriteLine("========================\n");
        }
    }
}