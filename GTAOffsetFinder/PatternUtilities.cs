using System.Text;

namespace GTAOffsetFinder
{
    /// <summary>
    /// Utilitários para trabalhar com patterns e offsets
    /// </summary>
    public static class PatternUtilities
    {
        /// <summary>
        /// Valida se um endereço parece ser um ponteiro válido
        /// </summary>
        public static bool IsValidPointer(IntPtr ptr)
        {
            long addr = ptr.ToInt64();
            return addr > 0x10000 && addr < 0x7FFFFFFFFFFF;
        }

        /// <summary>
        /// Lê uma cadeia de ponteiros (pointer chain)
        /// Exemplo: base + offset1 -> + offset2 -> + offset3
        /// </summary>
        public static IntPtr FollowPointerChain(GuardLinkDriver driver, int processId, IntPtr baseAddr, params int[] offsets)
        {
            IntPtr current = baseAddr;

            for (int i = 0; i < offsets.Length; i++)
            {
                try
                {
                    if (i < offsets.Length - 1)
                    {
                        // Não é o último offset, então precisa ler o ponteiro
                        current = driver.Read<IntPtr>(processId, IntPtr.Add(current, offsets[i]));

                        if (!IsValidPointer(current))
                            return IntPtr.Zero;
                    }
                    else
                    {
                        // Último offset, apenas adiciona
                        current = IntPtr.Add(current, offsets[i]);
                    }
                }
                catch
                {
                    return IntPtr.Zero;
                }
            }

            return current;
        }

        /// <summary>
        /// Gera um arquivo JSON com os resultados
        /// </summary>
        public static void ExportToJson(Dictionary<string, ScanResult> results, string filename)
        {
            var sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine($"  \"timestamp\": \"{DateTime.Now:yyyy-MM-dd HH:mm:ss}\",");
            sb.AppendLine("  \"patterns\": {");

            var resultsList = results.Where(x => x.Value.Found).ToList();
            for (int i = 0; i < resultsList.Count; i++)
            {
                var kvp = resultsList[i];
                var result = kvp.Value;

                sb.AppendLine($"    \"{result.PatternName}\": {{");
                sb.AppendLine($"      \"patternOffset\": \"0x{result.PatternOffset:X}\",");
                sb.AppendLine($"      \"finalOffset\": \"0x{result.FinalOffset:X}\",");
                sb.AppendLine($"      \"address\": \"0x{result.Address.ToInt64():X}\",");
                sb.AppendLine($"      \"valid\": {result.IsValid.ToString().ToLower()}");
                sb.Append($"    }}");

                if (i < resultsList.Count - 1)
                    sb.AppendLine(",");
                else
                    sb.AppendLine();
            }

            sb.AppendLine("  }");
            sb.AppendLine("}");

            System.IO.File.WriteAllText(filename, sb.ToString());
        }

        /// <summary>
        /// Gera um arquivo de header C++ com os offsets
        /// </summary>
        public static void ExportToCppHeader(Dictionary<string, ScanResult> results, string filename, IntPtr baseAddress)
        {
            var sb = new StringBuilder();
            sb.AppendLine("#pragma once");
            sb.AppendLine("// ==================== GTA V OFFSETS ====================");
            sb.AppendLine($"// Generated: {DateTime.Now}");
            sb.AppendLine($"// Base Address: 0x{baseAddress.ToInt64():X}");
            sb.AppendLine();
            sb.AppendLine("namespace GTA5 {");
            sb.AppendLine("namespace Offsets {");
            sb.AppendLine();

            foreach (var kvp in results.Where(x => x.Value.Found).OrderBy(x => x.Key))
            {
                var result = kvp.Value;
                string varName = kvp.Key.Replace(" ", "_").Replace("-", "_").ToUpper();
                string comment = result.IsValid ? "// Validated" : "// Unvalidated";
                sb.AppendLine($"    constexpr uintptr_t {varName} = 0x{result.FinalOffset:X}; {comment}");
            }

            sb.AppendLine();
            sb.AppendLine("    // Player Structure Offsets");
            sb.AppendLine("    constexpr int PLAYER_HEALTH = 0x280;");
            sb.AppendLine("    constexpr int PLAYER_MAX_HEALTH = 0x2A0;");
            sb.AppendLine("    constexpr int PLAYER_ARMOR = 0x14B0;");
            sb.AppendLine("    constexpr int PLAYER_VISUAL_X = 0x90;");
            sb.AppendLine("    constexpr int PLAYER_VISUAL_Y = 0x94;");
            sb.AppendLine("    constexpr int PLAYER_VISUAL_Z = 0x98;");
            sb.AppendLine();
            sb.AppendLine("} // namespace Offsets");
            sb.AppendLine("} // namespace GTA5");

            System.IO.File.WriteAllText(filename, sb.ToString());
        }

        /// <summary>
        /// Gera um arquivo Python com os offsets
        /// </summary>
        public static void ExportToPython(Dictionary<string, ScanResult> results, string filename, IntPtr baseAddress)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# ==================== GTA V OFFSETS ====================");
            sb.AppendLine($"# Generated: {DateTime.Now}");
            sb.AppendLine($"# Base Address: 0x{baseAddress.ToInt64():X}");
            sb.AppendLine();
            sb.AppendLine("class GTA5Offsets:");
            sb.AppendLine($"    BASE_ADDRESS = 0x{baseAddress.ToInt64():X}");
            sb.AppendLine();

            foreach (var kvp in results.Where(x => x.Value.Found).OrderBy(x => x.Key))
            {
                var result = kvp.Value;
                string varName = kvp.Key.Replace(" ", "_").Replace("-", "_").ToUpper();
                string comment = result.IsValid ? "# Validated" : "# Unvalidated";
                sb.AppendLine($"    {varName} = 0x{result.FinalOffset:X}  {comment}");
            }

            sb.AppendLine();
            sb.AppendLine("    # Player Structure Offsets");
            sb.AppendLine("    PLAYER_HEALTH = 0x280");
            sb.AppendLine("    PLAYER_MAX_HEALTH = 0x2A0");
            sb.AppendLine("    PLAYER_ARMOR = 0x14B0");
            sb.AppendLine("    PLAYER_VISUAL_X = 0x90");
            sb.AppendLine("    PLAYER_VISUAL_Y = 0x94");
            sb.AppendLine("    PLAYER_VISUAL_Z = 0x98");

            System.IO.File.WriteAllText(filename, sb.ToString());
        }

        /// <summary>
        /// Converte bytes para string de pattern
        /// </summary>
        public static string BytesToPattern(byte[] bytes, byte[] mask = null)
        {
            var sb = new StringBuilder();

            for (int i = 0; i < bytes.Length; i++)
            {
                if (mask != null && mask[i] == 0)
                {
                    sb.Append("? ");
                }
                else
                {
                    sb.Append($"{bytes[i]:X2} ");
                }
            }

            return sb.ToString().Trim();
        }

        /// <summary>
        /// Cria um pattern a partir de um endereço conhecido
        /// (útil para criar signatures de funções)
        /// </summary>
        public static Pattern CreatePatternFromAddress(
            GuardLinkDriver driver,
            int processId,
            IntPtr address,
            int length,
            string name)
        {
            try
            {
                byte[] bytes = driver.ReadMemory(processId, address, length);
                string signature = BytesToPattern(bytes);

                return Pattern.Create(name, signature, OffsetType.Absolute);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to create pattern from address: {ex.Message}");
            }
        }

        /// <summary>
        /// Compara dois conjuntos de resultados (útil para detectar mudanças entre versões)
        /// </summary>
        public static void CompareResults(
            Dictionary<string, ScanResult> oldResults,
            Dictionary<string, ScanResult> newResults)
        {
            Console.WriteLine("\n[*] Comparing scan results...\n");

            int unchanged = 0;
            int changed = 0;
            int newPatterns = 0;
            int missing = 0;

            foreach (var kvp in oldResults)
            {
                if (newResults.TryGetValue(kvp.Key, out var newResult))
                {
                    if (kvp.Value.FinalOffset == newResult.FinalOffset)
                    {
                        unchanged++;
                    }
                    else
                    {
                        changed++;
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine($"[CHANGED] {kvp.Key}:");
                        Console.WriteLine($"  Old: 0x{kvp.Value.FinalOffset:X}");
                        Console.WriteLine($"  New: 0x{newResult.FinalOffset:X}");
                        Console.ResetColor();
                    }
                }
                else
                {
                    missing++;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine($"[MISSING] {kvp.Key}");
                    Console.ResetColor();
                }
            }

            foreach (var kvp in newResults)
            {
                if (!oldResults.ContainsKey(kvp.Key))
                {
                    newPatterns++;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine($"[NEW] {kvp.Key}: 0x{kvp.Value.FinalOffset:X}");
                    Console.ResetColor();
                }
            }

            Console.WriteLine("\n" + new string('─', 50));
            Console.WriteLine($"Unchanged: {unchanged}");
            Console.WriteLine($"Changed:   {changed}");
            Console.WriteLine($"New:       {newPatterns}");
            Console.WriteLine($"Missing:   {missing}");
        }

        /// <summary>
        /// Calcula a similaridade entre dois patterns (útil para encontrar patterns semelhantes)
        /// </summary>
        public static double CalculatePatternSimilarity(Pattern p1, Pattern p2)
        {
            if (p1.Bytes.Length != p2.Bytes.Length)
                return 0.0;

            int matches = 0;
            for (int i = 0; i < p1.Bytes.Length; i++)
            {
                // Se ambos são wildcards ou ambos são iguais
                if ((!p1.Mask[i] && !p2.Mask[i]) ||
                    (p1.Mask[i] && p2.Mask[i] && p1.Bytes[i] == p2.Bytes[i]))
                {
                    matches++;
                }
            }

            return (double)matches / p1.Bytes.Length;
        }

        /// <summary>
        /// Gera um relatório HTML dos resultados
        /// </summary>
        public static void GenerateHtmlReport(
            Dictionary<string, ScanResult> results,
            string filename,
            IntPtr baseAddress,
            string gameVersion)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html>");
            sb.AppendLine("<head>");
            sb.AppendLine("    <meta charset='utf-8'>");
            sb.AppendLine("    <title>GTA V Pattern Scan Results</title>");
            sb.AppendLine("    <style>");
            sb.AppendLine("        body { font-family: 'Consolas', monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }");
            sb.AppendLine("        h1 { color: #4ec9b0; }");
            sb.AppendLine("        table { border-collapse: collapse; width: 100%; margin-top: 20px; }");
            sb.AppendLine("        th, td { border: 1px solid #3e3e3e; padding: 10px; text-align: left; }");
            sb.AppendLine("        th { background: #252526; color: #4ec9b0; }");
            sb.AppendLine("        tr:hover { background: #2d2d30; }");
            sb.AppendLine("        .found { color: #4ec9b0; }");
            sb.AppendLine("        .not-found { color: #f48771; }");
            sb.AppendLine("        .valid { color: #89d185; }");
            sb.AppendLine("        .invalid { color: #ce9178; }");
            sb.AppendLine("    </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("    <h1>GTA V Pattern Scan Results</h1>");
            sb.AppendLine($"    <p>Generated: {DateTime.Now}</p>");
            sb.AppendLine($"    <p>Base Address: 0x{baseAddress.ToInt64():X}</p>");
            sb.AppendLine($"    <p>Game Version: {gameVersion}</p>");
            sb.AppendLine("    <table>");
            sb.AppendLine("        <tr><th>Pattern Name</th><th>Status</th><th>Pattern Offset</th><th>Final Offset</th><th>Address</th><th>Validated</th></tr>");

            foreach (var kvp in results.OrderBy(x => x.Key))
            {
                var result = kvp.Value;
                string statusClass = result.Found ? "found" : "not-found";
                string validClass = result.IsValid ? "valid" : "invalid";
                string status = result.Found ? "✓ Found" : "✗ Not Found";
                string validated = result.IsValid ? "✓ Yes" : "✗ No";

                sb.AppendLine("        <tr>");
                sb.AppendLine($"            <td>{result.PatternName}</td>");
                sb.AppendLine($"            <td class='{statusClass}'>{status}</td>");

                if (result.Found)
                {
                    sb.AppendLine($"            <td>0x{result.PatternOffset:X}</td>");
                    sb.AppendLine($"            <td>0x{result.FinalOffset:X}</td>");
                    sb.AppendLine($"            <td>0x{result.Address.ToInt64():X}</td>");
                    sb.AppendLine($"            <td class='{validClass}'>{validated}</td>");
                }
                else
                {
                    sb.AppendLine($"            <td colspan='4' class='not-found'>N/A</td>");
                }

                sb.AppendLine("        </tr>");
            }

            sb.AppendLine("    </table>");

            // Estatísticas
            int found = results.Count(x => x.Value.Found);
            int valid = results.Count(x => x.Value.Found && x.Value.IsValid);

            sb.AppendLine("    <h2>Statistics</h2>");
            sb.AppendLine($"    <p>Total Patterns: {results.Count}</p>");
            sb.AppendLine($"    <p>Found: {found} ({(found * 100.0 / results.Count):F1}%)</p>");
            sb.AppendLine($"    <p>Validated: {valid} ({(valid * 100.0 / found):F1}%)</p>");

            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            System.IO.File.WriteAllText(filename, sb.ToString());
        }

        /// <summary>
        /// Detecta automaticamente o tipo de offset baseado no padrão
        /// </summary>
        public static OffsetType DetectOffsetType(string signature)
        {
            // RIP-relative: 48 8B 05/15/25/35/0D ? ? ? ?
            if (signature.Contains("48 8B 05") ||
                signature.Contains("48 8B 15") ||
                signature.Contains("48 8B 0D") ||
                signature.Contains("48 8D 05") ||
                signature.Contains("48 8D 15"))
            {
                return OffsetType.RelativeOffset;
            }

            // Outros padrões comuns de RIP-relative
            if (signature.Contains("4C 8D 05") ||
                signature.Contains("4C 8D 15") ||
                signature.Contains("83 3D"))
            {
                return OffsetType.RelativeOffset;
            }

            return OffsetType.Absolute;
        }

        /// <summary>
        /// Valida se um offset aponta para dados válidos
        /// </summary>
        public static bool ValidateOffset(
            GuardLinkDriver driver,
            int processId,
            IntPtr address,
            int expectedSize = 4)
        {
            try
            {
                byte[] data = driver.ReadMemory(processId, address, expectedSize);

                // Verifica se não é tudo zero ou tudo 0xFF
                bool allZero = data.All(b => b == 0);
                bool allFF = data.All(b => b == 0xFF);

                return !allZero && !allFF;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Cria um pattern genérico com wildcards no início e fim
        /// </summary>
        public static Pattern CreateFlexiblePattern(string name, string coreSignature)
        {
            // Adiciona wildcards no início e fim para maior flexibilidade
            string flexibleSignature = $"? ? {coreSignature} ? ?";
            return Pattern.Create(name, flexibleSignature, OffsetType.RelativeOffset);
        }

        /// <summary>
        /// Otimiza um pattern removendo wildcards desnecessários
        /// </summary>
        public static Pattern OptimizePattern(Pattern pattern)
        {
            // Remove wildcards do início
            int start = 0;
            while (start < pattern.Mask.Length && !pattern.Mask[start])
                start++;

            // Remove wildcards do fim
            int end = pattern.Mask.Length - 1;
            while (end >= 0 && !pattern.Mask[end])
                end--;

            if (start > 0 || end < pattern.Mask.Length - 1)
            {
                int newLength = end - start + 1;
                byte[] newBytes = new byte[newLength];
                bool[] newMask = new bool[newLength];

                Array.Copy(pattern.Bytes, start, newBytes, 0, newLength);
                Array.Copy(pattern.Mask, start, newMask, 0, newLength);

                return new Pattern
                {
                    Name = pattern.Name,
                    Signature = BytesToPattern(newBytes, newMask.Select(m => (byte)(m ? 1 : 0)).ToArray()),
                    Bytes = newBytes,
                    Mask = newMask,
                    Type = pattern.Type,
                    OffsetPosition = pattern.OffsetPosition - start,
                    InstructionLength = pattern.InstructionLength,
                    Validator = pattern.Validator
                };
            }

            return pattern;
        }

        /// <summary>
        /// Verifica se um pattern é válido (tem pelo menos alguns bytes fixos)
        /// </summary>
        public static bool IsValidPattern(Pattern pattern, int minFixedBytes = 3)
        {
            if (pattern == null || pattern.Bytes == null || pattern.Mask == null)
                return false;

            int fixedBytes = pattern.Mask.Count(m => m);
            return fixedBytes >= minFixedBytes;
        }

        /// <summary>
        /// Calcula a "qualidade" de um pattern (quanto maior, melhor)
        /// </summary>
        public static double CalculatePatternQuality(Pattern pattern)
        {
            if (!IsValidPattern(pattern, 1))
                return 0.0;

            // Porcentagem de bytes fixos
            double fixedRatio = pattern.Mask.Count(m => m) / (double)pattern.Mask.Length;

            // Bonus por ter bytes fixos consecutivos
            int maxConsecutive = 0;
            int current = 0;

            foreach (bool m in pattern.Mask)
            {
                if (m)
                {
                    current++;
                    maxConsecutive = Math.Max(maxConsecutive, current);
                }
                else
                {
                    current = 0;
                }
            }

            double consecutiveBonus = Math.Min(maxConsecutive / 10.0, 0.3);

            return fixedRatio * 0.7 + consecutiveBonus;
        }

        /// <summary>
        /// Gera um resumo executivo dos resultados
        /// </summary>
        public static string GenerateExecutiveSummary(Dictionary<string, ScanResult> results)
        {
            var sb = new StringBuilder();

            int total = results.Count;
            int found = results.Count(x => x.Value.Found);
            int valid = results.Count(x => x.Value.Found && x.Value.IsValid);
            int critical = results.Count(x => x.Value.Found && x.Key.Contains("World") || x.Key.Contains("Player"));

            sb.AppendLine("═══════════════════════════════════════════════");
            sb.AppendLine("           EXECUTIVE SUMMARY");
            sb.AppendLine("═══════════════════════════════════════════════");
            sb.AppendLine();
            sb.AppendLine($"Total Patterns Scanned:  {total}");
            sb.AppendLine($"Patterns Found:          {found} ({found * 100.0 / total:F1}%)");
            sb.AppendLine($"Patterns Validated:      {valid} ({(found > 0 ? valid * 100.0 / found : 0):F1}%)");
            sb.AppendLine($"Critical Patterns:       {critical}");
            sb.AppendLine();

            // Status geral
            string status;

            if (valid >= total * 0.8)
            {
                status = "EXCELLENT - All systems operational";
            }
            else if (valid >= total * 0.6)
            {
                status = "GOOD - Most patterns working";
            }
            else if (valid >= total * 0.4)
            {
                status = "PARTIAL - Some patterns missing";
            }
            else
            {
                status = "CRITICAL - Many patterns failed";
            }

            sb.AppendLine($"Overall Status: {status}");
            sb.AppendLine();

            // Patterns problemáticos
            var failed = results.Where(x => !x.Value.Found).ToList();
            if (failed.Any())
            {
                sb.AppendLine("Failed Patterns:");
                foreach (var f in failed.Take(5))
                {
                    sb.AppendLine($"  • {f.Key}");
                }
                if (failed.Count > 5)
                {
                    sb.AppendLine($"  ... and {failed.Count - 5} more");
                }
            }

            sb.AppendLine("═══════════════════════════════════════════════");

            return sb.ToString();
        }

        /// <summary>
        /// Salva resultados em formato binário para carregamento rápido
        /// </summary>
        public static void SaveBinaryCache(Dictionary<string, ScanResult> results, string filename)
        {
            using (var writer = new System.IO.BinaryWriter(System.IO.File.Open(filename, System.IO.FileMode.Create)))
            {
                // Magic number e versão
                writer.Write(0x47544135); // "GTA5" em hex
                writer.Write((byte)1);     // Versão do formato

                // Número de resultados
                writer.Write(results.Count);

                foreach (var kvp in results)
                {
                    writer.Write(kvp.Key);
                    writer.Write(kvp.Value.Found);

                    if (kvp.Value.Found)
                    {
                        writer.Write(kvp.Value.PatternOffset);
                        writer.Write(kvp.Value.FinalOffset);
                        writer.Write(kvp.Value.Address.ToInt64());
                        writer.Write(kvp.Value.IsValid);
                    }
                }
            }
        }

        /// <summary>
        /// Carrega resultados do cache binário
        /// </summary>
        public static Dictionary<string, ScanResult> LoadBinaryCache(string filename)
        {
            var results = new Dictionary<string, ScanResult>();

            if (!System.IO.File.Exists(filename))
                return results;

            try
            {
                using (var reader = new System.IO.BinaryReader(System.IO.File.Open(filename, System.IO.FileMode.Open)))
                {
                    // Verificar magic number
                    int magic = reader.ReadInt32();
                    if (magic != 0x47544135)
                        throw new Exception("Invalid cache file format");

                    byte version = reader.ReadByte();
                    if (version != 1)
                        throw new Exception("Unsupported cache version");

                    int count = reader.ReadInt32();

                    for (int i = 0; i < count; i++)
                    {
                        string name = reader.ReadString();
                        bool found = reader.ReadBoolean();

                        var result = new ScanResult
                        {
                            PatternName = name,
                            Found = found
                        };

                        if (found)
                        {
                            result.PatternOffset = reader.ReadInt32();
                            result.FinalOffset = reader.ReadInt32();
                            result.Address = new IntPtr(reader.ReadInt64());
                            result.IsValid = reader.ReadBoolean();
                        }

                        results[name] = result;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Failed to load binary cache: {ex.Message}");
                return new Dictionary<string, ScanResult>();
            }

            return results;
        }

        /// <summary>
        /// Gera um diff entre dois scans (útil para tracking de mudanças entre updates)
        /// </summary>
        public static void GenerateDiffReport(
            Dictionary<string, ScanResult> oldResults,
            Dictionary<string, ScanResult> newResults,
            string filename)
        {
            var sb = new StringBuilder();
            sb.AppendLine("# GTA V Pattern Diff Report");
            sb.AppendLine($"Generated: {DateTime.Now}");
            sb.AppendLine();
            sb.AppendLine("## Changed Patterns");
            sb.AppendLine();

            bool hasChanges = false;

            foreach (var kvp in oldResults)
            {
                if (newResults.TryGetValue(kvp.Key, out var newResult))
                {
                    if (kvp.Value.FinalOffset != newResult.FinalOffset)
                    {
                        hasChanges = true;
                        sb.AppendLine($"### {kvp.Key}");
                        sb.AppendLine($"- Old: `0x{kvp.Value.FinalOffset:X8}` @ `0x{kvp.Value.Address.ToInt64():X}`");
                        sb.AppendLine($"- New: `0x{newResult.FinalOffset:X8}` @ `0x{newResult.Address.ToInt64():X}`");
                        sb.AppendLine($"- Delta: `{newResult.FinalOffset - kvp.Value.FinalOffset:+#;-#;0}` bytes");
                        sb.AppendLine();
                    }
                }
            }

            if (!hasChanges)
            {
                sb.AppendLine("*No changes detected*");
            }

            sb.AppendLine();
            sb.AppendLine("## New Patterns");
            sb.AppendLine();

            bool hasNew = false;
            foreach (var kvp in newResults)
            {
                if (!oldResults.ContainsKey(kvp.Key))
                {
                    hasNew = true;
                    sb.AppendLine($"- **{kvp.Key}**: `0x{kvp.Value.FinalOffset:X8}`");
                }
            }

            if (!hasNew)
            {
                sb.AppendLine("*No new patterns*");
            }

            sb.AppendLine();
            sb.AppendLine("## Missing Patterns");
            sb.AppendLine();

            bool hasMissing = false;
            foreach (var kvp in oldResults)
            {
                if (!newResults.ContainsKey(kvp.Key))
                {
                    hasMissing = true;
                    sb.AppendLine($"- **{kvp.Key}** (was at `0x{kvp.Value.FinalOffset:X8}`)");
                }
            }

            if (!hasMissing)
            {
                sb.AppendLine("*No missing patterns*");
            }

            System.IO.File.WriteAllText(filename, sb.ToString());
        }
    }
}