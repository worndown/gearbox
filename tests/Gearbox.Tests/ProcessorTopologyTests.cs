using System.Buffers.Binary;

namespace Gearbox.Tests
{
    [TestClass]
    public class ProcessorTopologyTests
    {
        [TestMethod]
        [DataRow(10, 20, 10)]
        [DataRow(10, 2, 2)]
        [DataRow(1, 20, 1)]
        [DataRow(0, 20, 1)]
        [DataRow(10, 0, 1)]
        public void WorkerCount_PhysicalCoresAndRuntimeLimit_SelectsSafeCount(int physical, int available, int expected)
        {
            Assert.AreEqual(expected, ProcessorTopology.LimitWorkerCount(physical, available));
        }

        [TestMethod]
        public void WindowsTopology_SmtAndMultipleGroups_CountsCoreRecords()
        {
            byte[] first = WindowsCore(smt: true, groups: 1);
            byte[] second = WindowsCore(smt: false, groups: 2);
            byte[] other = new byte[8];
            BinaryPrimitives.WriteUInt32LittleEndian(other, 3); // NUMA relationship.
            BinaryPrimitives.WriteUInt32LittleEndian(other.AsSpan(4), 8);

            Assert.AreEqual(2, ProcessorTopology.CountWindowsCores(first.Concat(second).Concat(other).ToArray()));
        }

        [TestMethod]
        public void WindowsTopology_InvalidRecords_RejectsIncompleteTopology()
        {
            byte[] valid = WindowsCore(smt: true, groups: 1);
            Assert.AreEqual(0, ProcessorTopology.CountWindowsCores(valid.AsSpan(0, valid.Length - 1)));
            Assert.AreEqual(0, ProcessorTopology.CountWindowsCores(valid.Concat(new byte[7]).ToArray()));
            BinaryPrimitives.WriteUInt32LittleEndian(valid.AsSpan(4), 0);
            Assert.AreEqual(0, ProcessorTopology.CountWindowsCores(valid));
            valid = WindowsCore(smt: true, groups: 1);
            BinaryPrimitives.WriteUInt16LittleEndian(valid.AsSpan(30), 2);
            Assert.AreEqual(0, ProcessorTopology.CountWindowsCores(valid));
        }

        [TestMethod]
        public void LinuxTopology_SmtSocketsAndOfflineProcessors_CountsDistinctOnlineCores()
        {
            Assert.AreEqual(3, ProcessorTopology.CountLinuxCores([
                (0, 0, true), (0, 0, true), (0, 1, true), (0, 1, true),
                (1, 0, true), (1, 0, true), (1, 1, false)
            ]));
            Assert.AreEqual(0, ProcessorTopology.CountLinuxCores([(0, -1, true)]));
            Assert.AreEqual(0, ProcessorTopology.CountLinuxCores([]));
        }

        [TestMethod]
        public void Discovery_UnavailableOrInvalidTopology_FallsBackToOneWorker()
        {
            Assert.AreEqual(1, ProcessorTopology.DiscoverPhysicalCoreCount(() => throw new IOException()));
            Assert.AreEqual(1, ProcessorTopology.DiscoverPhysicalCoreCount(() => throw new UnauthorizedAccessException()));
            Assert.AreEqual(1, ProcessorTopology.DiscoverPhysicalCoreCount(() => throw new DllNotFoundException()));
            Assert.AreEqual(1, ProcessorTopology.DiscoverPhysicalCoreCount(() => 0));
            Assert.AreEqual(10, ProcessorTopology.DiscoverPhysicalCoreCount(() => 10));
        }

        [TestMethod]
        public void Discovery_CurrentPlatform_ReturnsCountWithinRuntimeCapacity()
        {
            Assert.IsTrue(ProcessorTopology.WorkerCount >= 1);
            Assert.IsTrue(ProcessorTopology.WorkerCount <= Environment.ProcessorCount);
        }

        private static byte[] WindowsCore(bool smt, ushort groups)
        {
            byte[] record = new byte[32 + groups * (IntPtr.Size + 8)];
            BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(4), (uint)record.Length);
            record[8] = smt ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(30), groups);
            return record;
        }
    }
}
