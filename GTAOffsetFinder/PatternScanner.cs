using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace GTAOffsetFinder
{
    /// <summary>
    /// Advanced Pattern Scanner inspired by HorseMenu
    /// Supports multiple pattern formats, batch scanning, and automatic validation
    /// </summary>
    public class PatternScanner
    {
        private readonly GuardLinkDriver _driver;
        private readonly int _processId;
        private readonly IntPtr _baseAddress;
        private readonly long _moduleSize;

        // Cache para patterns já encontrados
        private readonly Dictionary<string, ScanResult> _cache = new Dictionary<string, ScanResult>();

        // Configurações
        public int ChunkSize { get; set; } = 0x100000; // 1MB chunks
        public bool UseCache { get; set; } = true;
        public bool VerboseLogging { get; set; } = false;

        public PatternScanner(GuardLinkDriver driver, Process process)
        {
            _driver = driver ?? throw new ArgumentNullException(nameof(driver));
            _processId = process.Id;
            _baseAddress = driver.GetModuleBase(process.Id, "GTA5.exe");
            _moduleSize = process.MainModule.ModuleMemorySize;

            if (_baseAddress == IntPtr.Zero)
                throw new Exception("Failed to get module base address");
        }

        /// <summary>
        /// Encontra um pattern e retorna o endereço absoluto
        /// </summary>
        public ScanResult Scan(Pattern pattern)
        {
            if (UseCache && _cache.TryGetValue(pattern.Name, out var cached))
            {
                if (VerboseLogging)
                    Console.WriteLine($"[CACHE] {pattern.Name}: 0x{cached.FinalOffset:X}");
                return cached;
            }

            var result = ScanInternal(pattern);

            if (UseCache && result.Found)
            {
                _cache[pattern.Name] = result;
            }

            return result;
        }

        /// <summary>
        /// Escaneia múltiplos patterns de uma vez (mais eficiente)
        /// </summary>
        public Dictionary<string, ScanResult> BatchScan(IEnumerable<Pattern> patterns)
        {
            var results = new Dictionary<string, ScanResult>();
            var patternsToScan = new List<Pattern>();

            // Separar patterns já em cache
            foreach (var pattern in patterns)
            {
                if (UseCache && _cache.TryGetValue(pattern.Name, out var cached))
                {
                    results[pattern.Name] = cached;
                }
                else
                {
                    patternsToScan.Add(pattern);
                }
            }

            if (patternsToScan.Count == 0)
                return results;

            // Escanear todos de uma vez
            Console.WriteLine($"[*] Batch scanning {patternsToScan.Count} patterns...");

            for (long offset = 0; offset < _moduleSize; offset += ChunkSize)
            {
                int size = (int)Math.Min(ChunkSize, _moduleSize - offset);

                try
                {
                    byte[] chunk = _driver.ReadMemory(_processId, IntPtr.Add(_baseAddress, (int)offset), size);

                    // Procurar todos os patterns neste chunk
                    foreach (var pattern in patternsToScan.ToList())
                    {
                        if (results.ContainsKey(pattern.Name))
                            continue;

                        int index = FindInBuffer(chunk, pattern);
                        if (index != -1)
                        {
                            var result = ProcessMatch(pattern, (int)(offset + index), chunk, index);
                            results[pattern.Name] = result;

                            if (UseCache)
                                _cache[pattern.Name] = result;

                            patternsToScan.Remove(pattern);
                        }
                    }
                }
                catch { }

                if (patternsToScan.Count == 0)
                    break;
            }

            // Patterns não encontrados
            foreach (var pattern in patternsToScan)
            {
                results[pattern.Name] = new ScanResult
                {
                    PatternName = pattern.Name,
                    Found = false
                };
            }

            return results;
        }

        private ScanResult ScanInternal(Pattern pattern)
        {
            if (VerboseLogging)
                Console.WriteLine($"[SCAN] {pattern.Name}: {pattern.Signature}");

            for (long offset = 0; offset < _moduleSize; offset += ChunkSize)
            {
                int size = (int)Math.Min(ChunkSize, _moduleSize - offset);

                try
                {
                    byte[] chunk = _driver.ReadMemory(_processId, IntPtr.Add(_baseAddress, (int)offset), size);
                    int index = FindInBuffer(chunk, pattern);

                    if (index != -1)
                    {
                        return ProcessMatch(pattern, (int)(offset + index), chunk, index);
                    }
                }
                catch (Exception ex)
                {
                    if (VerboseLogging)
                        Console.WriteLine($"[ERROR] Chunk at 0x{offset:X}: {ex.Message}");
                }
            }

            return new ScanResult
            {
                PatternName = pattern.Name,
                Found = false
            };
        }

        private ScanResult ProcessMatch(Pattern pattern, int patternOffset, byte[] chunk, int chunkIndex)
        {
            var result = new ScanResult
            {
                PatternName = pattern.Name,
                Found = true,
                PatternOffset = patternOffset
            };

            try
            {
                // Processar offset baseado no tipo
                switch (pattern.Type)
                {
                    case OffsetType.Absolute:
                        result.FinalOffset = patternOffset;
                        result.Address = IntPtr.Add(_baseAddress, patternOffset);
                        break;

                    case OffsetType.RelativeOffset:
                        // Ler offset relativo (RIP-relative addressing)
                        int relOffset = BitConverter.ToInt32(chunk, chunkIndex + pattern.OffsetPosition);
                        result.RelativeOffset = relOffset;
                        result.FinalOffset = patternOffset + pattern.InstructionLength + relOffset;
                        result.Address = IntPtr.Add(_baseAddress, result.FinalOffset);
                        break;

                    case OffsetType.Pointer:
                        // Ler ponteiro direto
                        result.FinalOffset = patternOffset + pattern.OffsetPosition;
                        result.Address = IntPtr.Add(_baseAddress, result.FinalOffset);
                        break;
                }

                // Validação automática
                if (pattern.Validator != null)
                {
                    result.IsValid = pattern.Validator(_driver, _processId, result.Address);
                }
                else
                {
                    result.IsValid = true;
                }

                if (VerboseLogging)
                {
                    Console.WriteLine($"[FOUND] {pattern.Name}:");
                    Console.WriteLine($"  Pattern at:  0x{result.PatternOffset:X}");
                    Console.WriteLine($"  Final:       0x{result.FinalOffset:X}");
                    Console.WriteLine($"  Address:     0x{result.Address.ToInt64():X}");
                    Console.WriteLine($"  Valid:       {result.IsValid}");
                }
            }
            catch (Exception ex)
            {
                result.IsValid = false;
                result.Error = ex.Message;
            }

            return result;
        }

        private int FindInBuffer(byte[] buffer, Pattern pattern)
        {
            for (int i = 0; i <= buffer.Length - pattern.Bytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Bytes.Length; j++)
                {
                    if (pattern.Mask[j] && buffer[i + j] != pattern.Bytes[j])
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                    return i;
            }

            return -1;
        }

        /// <summary>
        /// Limpa o cache de patterns
        /// </summary>
        public void ClearCache()
        {
            _cache.Clear();
        }

        /// <summary>
        /// Exporta os resultados do cache para arquivo
        /// </summary>
        public void ExportCache(string filename)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Pattern Scanner Cache");
            sb.AppendLine($"// Generated: {DateTime.Now}");
            sb.AppendLine();

            foreach (var kvp in _cache)
            {
                var result = kvp.Value;
                if (result.Found)
                {
                    sb.AppendLine($"// {result.PatternName}");
                    sb.AppendLine($"Pattern:  0x{result.PatternOffset:X}");
                    sb.AppendLine($"Offset:   0x{result.FinalOffset:X}");
                    sb.AppendLine($"Address:  0x{result.Address.ToInt64():X}");
                    sb.AppendLine($"Valid:    {result.IsValid}");
                    sb.AppendLine();
                }
            }

            System.IO.File.WriteAllText(filename, sb.ToString());
        }
    }

    /// <summary>
    /// Representa um pattern de busca
    /// </summary>
    public class Pattern
    {
        public string Name { get; set; }
        public string Signature { get; set; }
        public byte[] Bytes { get; set; }
        public bool[] Mask { get; set; }
        public OffsetType Type { get; set; } = OffsetType.Absolute;
        public int OffsetPosition { get; set; } = 3; // Posição do offset no pattern (geralmente 3 para RIP-relative)
        public int InstructionLength { get; set; } = 7; // Tamanho da instrução completa
        public Func<GuardLinkDriver, int, IntPtr, bool> Validator { get; set; }

        public static Pattern Create(string name, string signature, OffsetType type = OffsetType.RelativeOffset)
        {
            var (bytes, mask) = ParseSignature(signature);

            return new Pattern
            {
                Name = name,
                Signature = signature,
                Bytes = bytes,
                Mask = mask,
                Type = type,
                OffsetPosition = 3,
                InstructionLength = 7
            };
        }

        public static Pattern CreateWithValidator(
            string name,
            string signature,
            OffsetType type,
            Func<GuardLinkDriver, int, IntPtr, bool> validator)
        {
            var pattern = Create(name, signature, type);
            pattern.Validator = validator;
            return pattern;
        }

        private static (byte[] bytes, bool[] mask) ParseSignature(string signature)
        {
            var parts = signature.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var bytes = new byte[parts.Length];
            var mask = new bool[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == "?" || parts[i] == "??")
                {
                    bytes[i] = 0;
                    mask[i] = false;
                }
                else
                {
                    bytes[i] = Convert.ToByte(parts[i], 16);
                    mask[i] = true;
                }
            }

            return (bytes, mask);
        }
    }

    public enum OffsetType
    {
        Absolute,           // Offset direto
        RelativeOffset,     // RIP-relative (48 8B 05 ? ? ? ?)
        Pointer             // Ponteiro direto
    }

    /// <summary>
    /// Resultado de um scan
    /// </summary>
    public class ScanResult
    {
        public string PatternName { get; set; }
        public bool Found { get; set; }
        public int PatternOffset { get; set; }      // Onde o pattern foi encontrado
        public int RelativeOffset { get; set; }     // Offset relativo lido
        public int FinalOffset { get; set; }        // Offset final calculado
        public IntPtr Address { get; set; }         // Endereço absoluto
        public bool IsValid { get; set; }           // Validação passou
        public string Error { get; set; }

        public override string ToString()
        {
            if (!Found)
                return $"{PatternName}: Not found";

            return $"{PatternName}: Pattern=0x{PatternOffset:X}, Final=0x{FinalOffset:X}, Valid={IsValid}";
        }
    }
}