using System;
using System.Collections.Generic;

namespace GTAOffsetFinder
{
    /// <summary>
    /// Definições de patterns do GTA V
    /// Baseado no HorseMenu e outras fontes públicas
    /// </summary>
    public static class GTAPatterns
    {
        /// <summary>
        /// Obtém todos os patterns definidos
        /// </summary>
        public static List<Pattern> GetAllPatterns()
        {
            return new List<Pattern>
            {
                // ============ CORE POINTERS ============
                
                GetWorldPattern(),
                GetBlipListPattern(),
                GetWeatherPattern(),
                GetClockPattern(),
                GetReplayInterfacePattern(),
                
                // ============ PLAYER ============
                
                GetPlayerInfoPattern(),
                GetPlayerPedFactoryPattern(),
                
                // ============ VEHICLE ============
                
                GetVehiclePoolPattern(),
                GetVehicleHandlingPattern(),
                
                // ============ NETWORK ============
                
                GetNetworkPlayerMgrPattern(),
                GetNetworkObjectMgrPattern(),
                GetSessionPattern(),
                
                // ============ GAME STATE ============
                
                GetGameStatePattern(),
                GetFrameCountPattern(),
                GetIsSessionStartedPattern(),
                
                // ============ SCRIPT ============
                
                GetScriptThreadsPattern(),
                GetScriptGlobalsPattern(),
                
                // ============ FUNCTIONS ============
                
                GetModelSpawnBypassPattern(),
                GetNativeRegistrationPattern(),
            };
        }

        // ============ WORLD & CORE ============

        private static Pattern GetWorldPattern()
        {
            return Pattern.CreateWithValidator(
                "World",
                "48 8B 05 ? ? ? ? 45 ? ? ? ? 48 8B 48 08 48 85 C9",
                OffsetType.RelativeOffset,
                ValidateWorld
            );
        }

        private static Pattern GetBlipListPattern()
        {
            return Pattern.Create(
                "BlipList",
                "4C 8D 05 ? ? ? ? 0F B7 C1",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetWeatherPattern()
        {
            return Pattern.Create(
                "Weather",
                "48 8D 15 ? ? ? ? 48 8B CF E8 ? ? ? ? 48 8B 1D",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetClockPattern()
        {
            return Pattern.Create(
                "Clock",
                "48 8B 0D ? ? ? ? 48 85 C9 74 ? 8B 51 20 8B 41 24",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetReplayInterfacePattern()
        {
            return Pattern.Create(
                "ReplayInterface",
                "48 8D 0D ? ? ? ? 48 8B D7 E8 ? ? ? ? 48 8D 0D ? ? ? ? 8A D8 E8 ? ? ? ? 84 DB 75 13 48 8D 0D",
                OffsetType.RelativeOffset
            );
        }

        // ============ PLAYER ============

        private static Pattern GetPlayerInfoPattern()
        {
            return Pattern.Create(
                "PlayerInfo",
                "48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B CF",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetPlayerPedFactoryPattern()
        {
            return Pattern.CreateWithValidator(
                "PlayerPedFactory",
                "48 8B 05 ? ? ? ? 48 8B 48 08 48 85 C9 74 52",
                OffsetType.RelativeOffset,
                ValidatePlayerPedFactory
            );
        }

        // ============ VEHICLE ============

        private static Pattern GetVehiclePoolPattern()
        {
            return Pattern.Create(
                "VehiclePool",
                "48 8B 05 ? ? ? ? F3 0F 59 F6 48 8B 40 08",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetVehicleHandlingPattern()
        {
            return Pattern.Create(
                "VehicleHandling",
                "48 85 C0 74 3F 48 8B 40 ? 48 85 C0 74 36",
                OffsetType.Absolute
            );
        }

        // ============ NETWORK ============

        private static Pattern GetNetworkPlayerMgrPattern()
        {
            return Pattern.CreateWithValidator(
                "NetworkPlayerMgr",
                "48 8B 0D ? ? ? ? 8A D3 48 8B 01 FF 50 ? 4C 8B 07 48 8B CF",
                OffsetType.RelativeOffset,
                ValidateNetworkPlayerMgr
            );
        }

        private static Pattern GetNetworkObjectMgrPattern()
        {
            return Pattern.Create(
                "NetworkObjectMgr",
                "48 8B 0D ? ? ? ? 45 33 C0 E8 ? ? ? ? 33 FF 4C 8B F0",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetSessionPattern()
        {
            return Pattern.Create(
                "Session",
                "48 8B 0D ? ? ? ? 48 8B D3 E8 ? ? ? ? 84 C0 75 14",
                OffsetType.RelativeOffset
            );
        }

        // ============ GAME STATE ============

        private static Pattern GetGameStatePattern()
        {
            return Pattern.Create(
                "GameState",
                "83 3D ? ? ? ? ? 8A D9 74 0A",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetFrameCountPattern()
        {
            return Pattern.Create(
                "FrameCount",
                "8B 15 ? ? ? ? 41 FF CF",
                OffsetType.RelativeOffset
            );
        }

        private static Pattern GetIsSessionStartedPattern()
        {
            return Pattern.Create(
                "IsSessionStarted",
                "40 38 35 ? ? ? ? 75 0E 4C 8B C3 49 8B D7 49 8B CE",
                OffsetType.RelativeOffset
            );
        }

        // ============ SCRIPT ============

        private static Pattern GetScriptThreadsPattern()
        {
            return Pattern.Create(
                "ScriptThreads",
                "45 33 F6 8B E9 85 C9 B8",
                OffsetType.Absolute
            );
        }

        private static Pattern GetScriptGlobalsPattern()
        {
            return Pattern.Create(
                "ScriptGlobals",
                "48 8D 15 ? ? ? ? 4C 8B C0 E8 ? ? ? ? 48 85 FF 48 89 1D",
                OffsetType.RelativeOffset
            );
        }

        // ============ FUNCTIONS ============

        private static Pattern GetModelSpawnBypassPattern()
        {
            return Pattern.Create(
                "ModelSpawnBypass",
                "48 8B C8 FF 52 30 84 C0 74 05 48",
                OffsetType.Absolute
            );
        }

        private static Pattern GetNativeRegistrationPattern()
        {
            return Pattern.Create(
                "NativeRegistration",
                "48 8D 0D ? ? ? ? 48 8B 14 FA 48 8B 01 FF 50 ? 48 85 C0 75",
                OffsetType.RelativeOffset
            );
        }

        // ============ VALIDATORS ============

        private static bool ValidateWorld(GuardLinkDriver driver, int pid, IntPtr address)
        {
            try
            {
                // Ler o ponteiro do World
                IntPtr worldPtr = driver.Read<IntPtr>(pid, address);
                if (!IsValidPointer(worldPtr))
                    return false;

                // Tentar ler o Player pointer em World+0x08
                IntPtr playerPtr = driver.Read<IntPtr>(pid, IntPtr.Add(worldPtr, 0x08));
                if (!IsValidPointer(playerPtr))
                    return false;

                // Validar que tem valores de saúde válidos
                float health = driver.Read<float>(pid, IntPtr.Add(playerPtr, 0x280));
                return health > 0 && health <= 1000;
            }
            catch
            {
                return false;
            }
        }

        private static bool ValidatePlayerPedFactory(GuardLinkDriver driver, int pid, IntPtr address)
        {
            try
            {
                IntPtr pedFactory = driver.Read<IntPtr>(pid, address);
                if (!IsValidPointer(pedFactory))
                    return false;

                IntPtr playerPed = driver.Read<IntPtr>(pid, IntPtr.Add(pedFactory, 0x08));
                return IsValidPointer(playerPed);
            }
            catch
            {
                return false;
            }
        }

        private static bool ValidateNetworkPlayerMgr(GuardLinkDriver driver, int pid, IntPtr address)
        {
            try
            {
                IntPtr netPlayerMgr = driver.Read<IntPtr>(pid, address);
                if (!IsValidPointer(netPlayerMgr))
                    return false;

                // Verificar se tem a estrutura esperada
                int playerCount = driver.Read<int>(pid, IntPtr.Add(netPlayerMgr, 0x0180));
                return playerCount >= 0 && playerCount <= 32;
            }
            catch
            {
                return false;
            }
        }

        private static bool IsValidPointer(IntPtr ptr)
        {
            long addr = ptr.ToInt64();
            return addr > 0x10000 && addr < 0x7FFFFFFFFFFF;
        }

        // ============ PATTERN GROUPS ============

        public static List<Pattern> GetEssentialPatterns()
        {
            return new List<Pattern>
            {
                GetWorldPattern(),
                GetPlayerPedFactoryPattern(),
                GetVehiclePoolPattern(),
                GetNetworkPlayerMgrPattern(),
            };
        }

        public static List<Pattern> GetNetworkPatterns()
        {
            return new List<Pattern>
            {
                GetNetworkPlayerMgrPattern(),
                GetNetworkObjectMgrPattern(),
                GetSessionPattern(),
                GetIsSessionStartedPattern(),
            };
        }

        public static List<Pattern> GetScriptPatterns()
        {
            return new List<Pattern>
            {
                GetScriptThreadsPattern(),
                GetScriptGlobalsPattern(),
                GetNativeRegistrationPattern(),
            };
        }
    }
}