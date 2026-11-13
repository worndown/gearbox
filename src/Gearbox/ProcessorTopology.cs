using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security;

namespace Gearbox
{
    internal static class ProcessorTopology
    {
        private const int ProcessorCoreRelationship = 0;
        private const int InsufficientBuffer = 122;
        private static readonly Lazy<int> PhysicalCoreCount = new Lazy<int>(() => DiscoverPhysicalCoreCount(ProbePhysicalCoreCount));

        public static int WorkerCount => LimitWorkerCount(PhysicalCoreCount.Value, Environment.ProcessorCount);

        internal static int LimitWorkerCount(int physicalCores, int availableProcessors) =>
            Math.Min(Math.Max(1, physicalCores), Math.Max(1, availableProcessors));

        internal static int DiscoverPhysicalCoreCount(Func<int> probe)
        {
            try
            {
                return Math.Max(1, probe());
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
                or SecurityException or NotSupportedException or DllNotFoundException
                or EntryPointNotFoundException or FormatException or OverflowException)
            {
                return 1;
            }
        }

        private static int ProbePhysicalCoreCount()
        {
            if (OperatingSystem.IsWindows())
            {
                return GetWindowsPhysicalCoreCount();
            }
            if (OperatingSystem.IsLinux())
            {
                return CountLinuxCores(ReadLinuxProcessors());
            }
            if (OperatingSystem.IsMacOS())
            {
                nuint length = sizeof(int);
                return SysctlByName("hw.physicalcpu", out int count, ref length, IntPtr.Zero, 0) == 0
                    && length == sizeof(int) ? count : 1;
            }

            return 1;
        }

        private static int GetWindowsPhysicalCoreCount()
        {
            uint length = 0;
            if (!GetLogicalProcessorInformationEx(ProcessorCoreRelationship, null, ref length)
                && Marshal.GetLastPInvokeError() != InsufficientBuffer)
            {
                return 1;
            }

            // Retry if processor topology changes between the size query and the read.
            for (int attempt = 0; attempt < 3 && length > 0; attempt++)
            {
                byte[] buffer = new byte[checked((int)length)];
                if (GetLogicalProcessorInformationEx(ProcessorCoreRelationship, buffer, ref length))
                {
                    return length <= buffer.Length ? CountWindowsCores(buffer.AsSpan(0, (int)length)) : 1;
                }
                if (Marshal.GetLastPInvokeError() != InsufficientBuffer)
                {
                    break;
                }
            }

            return 1;
        }

        internal static int CountWindowsCores(ReadOnlySpan<byte> records)
        {
            int count = 0;
            while (!records.IsEmpty)
            {
                if (records.Length < 8)
                {
                    return 0;
                }

                uint relationship = BinaryPrimitives.ReadUInt32LittleEndian(records);
                uint size = BinaryPrimitives.ReadUInt32LittleEndian(records[4..]);
                if (size < 8 || size > records.Length)
                {
                    return 0;
                }

                if (relationship == ProcessorCoreRelationship)
                {
                    if (size < 32)
                    {
                        return 0;
                    }
                    int groupCount = BinaryPrimitives.ReadUInt16LittleEndian(records[30..]);
                    if (groupCount == 0 || size < 32 + groupCount * (IntPtr.Size + 8))
                    {
                        return 0;
                    }
                    // A core is one record, regardless of SMT flags or processor groups.
                    count++;
                }

                records = records[(int)size..];
            }

            return count;
        }

        private static IEnumerable<(int PackageId, int CoreId, bool Online)> ReadLinuxProcessors()
        {
            foreach (string directory in Directory.EnumerateDirectories("/sys/devices/system/cpu", "cpu*"))
            {
                string name = Path.GetFileName(directory);
                if (!int.TryParse(name.AsSpan(3), out _))
                {
                    continue;
                }

                string onlinePath = Path.Combine(directory, "online");
                if (File.Exists(onlinePath) && File.ReadAllText(onlinePath).Trim() == "0")
                {
                    continue;
                }

                int packageId = int.Parse(File.ReadAllText(Path.Combine(directory, "topology", "physical_package_id")));
                int coreId = int.Parse(File.ReadAllText(Path.Combine(directory, "topology", "core_id")));
                yield return (packageId, coreId, true);
            }
        }

        internal static int CountLinuxCores(IEnumerable<(int PackageId, int CoreId, bool Online)> processors)
        {
            HashSet<(int, int)> cores = new HashSet<(int, int)>();
            foreach (var processor in processors)
            {
                if (!processor.Online)
                {
                    continue;
                }
                if (processor.PackageId < 0 || processor.CoreId < 0)
                {
                    return 0;
                }

                cores.Add((processor.PackageId, processor.CoreId));
            }

            return cores.Count;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetLogicalProcessorInformationEx(int relationship, [Out] byte[]? buffer, ref uint length);

        [DllImport("libSystem.B.dylib", EntryPoint = "sysctlbyname")]
        private static extern int SysctlByName([MarshalAs(UnmanagedType.LPUTF8Str)] string name,
            out int value, ref nuint length, IntPtr newValue, nuint newLength);
    }
}
