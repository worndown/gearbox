using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Gearbox.Tests
{
    [TestClass]
    public class FileGlobTests
    {
        private string root = null!;
        private readonly List<string> links = [];

        [TestInitialize]
        public void Initialize()
        {
            this.links.Clear();
            this.root = Path.Combine(Path.GetTempPath(), "Gearbox.FileGlobTests." + Guid.NewGuid().ToString("N"));
            this.CreateFile("root.txt");
            this.CreateFile("README.md");
            this.CreateFile("dir1/one.txt");
            this.CreateFile("dir1/nested/deep.txt");
            this.CreateFile("dir2/two.txt");
            Directory.CreateDirectory(this.FullPath("empty"));
            Directory.CreateDirectory(this.FullPath("named.txt"));
        }

        [TestCleanup]
        public void Cleanup()
        {
            foreach (string link in this.links)
            {
                // Remove links before recursively deleting their targets.
                Directory.Delete(link);
            }

            Directory.Delete(this.root, true);
        }

        [TestMethod]
        [DataRow("root.txt", "root.txt")]
        [DataRow("missing.txt", "")]
        [DataRow("empty", "")]
        [DataRow("named.txt", "")]
        [DataRow("*", "README.md|root.txt")]
        [DataRow("*.txt", "root.txt")]
        [DataRow("empty/*", "")]
        [DataRow("missing/*.txt", "")]
        [DataRow("ROOT.*", "root.txt")]
        [DataRow("root.tx?", "root.txt")]
        [DataRow("root.tx??", "")]
        [DataRow("r*t.txt", "root.txt")]
        [DataRow("[Rr]*.txt", "root.txt")]
        [DataRow("[a-q]*.txt", "")]
        [DataRow("[^r]*.txt", "")]
        [DataRow("dir[1-2]/*.txt", "dir1/one.txt|dir2/two.txt")]
        [DataRow("dir?/nested/*.txt", "dir1/nested/deep.txt")]
        [DataRow("dir*/one.txt", "dir1/one.txt")]
        [DataRow("dir*/ONE.txt", "dir1/one.txt")]
        [DataRow("dir*/o?e.txt", "dir1/one.txt")]
        [DataRow("dir*/*.txt", "dir1/one.txt|dir2/two.txt")]
        [DataRow("dir*/missing.txt", "")]
        [DataRow("dir*/missing/*.txt", "")]
        [DataRow("no*/root.txt", "")]
        [DataRow("no*/../root.txt", "")]
        [DataRow("dir*/missing/../root.txt", "")]
        [DataRow("dir**/*.txt", "dir1/one.txt|dir2/two.txt")]
        [DataRow("dir[^2]/*.txt", "dir1/one.txt")]
        [DataRow("**.txt", "root.txt")]
        [DataRow("***", "README.md|root.txt")]
        [DataRow("./root.txt", "root.txt")]
        [DataRow("dir1/../root.txt", "root.txt")]
        [DataRow("dir*/./*.txt", "dir1/one.txt|dir2/two.txt")]
        [DataRow("dir*/../root.txt", "root.txt")]
        [DataRow("dir*/../dir1/nested/deep.txt", "dir1/nested/deep.txt")]
        [DataRow("dir*/nested/../one.txt", "dir1/one.txt")]
        [DataRow("dir*/nested/../../root.txt", "root.txt")]
        [DataRow("dir*/../dir*/../root.txt", "root.txt")]
        [DataRow("**/*.txt", "root.txt|dir1/one.txt|dir1/nested/deep.txt|dir2/two.txt")]
        [DataRow("**/root.txt", "root.txt")]
        [DataRow("dir1/**/one.txt", "dir1/one.txt")]
        [DataRow("dir1/**/deep.txt", "dir1/nested/deep.txt")]
        [DataRow("dir1/**", "dir1/one.txt|dir1/nested/deep.txt")]
        [DataRow("**", "root.txt|README.md|dir1/one.txt|dir1/nested/deep.txt|dir2/two.txt")]
        [DataRow("**/**/**/deep.txt", "dir1/nested/deep.txt")]
        [DataRow("**/*/../root.txt", "root.txt")]
        [DataRow("**/./*.txt", "root.txt|dir1/one.txt|dir1/nested/deep.txt|dir2/two.txt")]
        [DataRow("dir*/*/**/deep.txt", "dir1/nested/deep.txt")]
        [DataRow("**/nested/../one.txt", "dir1/one.txt")]
        [DataRow("dir*/**/../root.txt", "root.txt")]
        [DataRow("**/dir*/**/*.txt", "dir1/one.txt|dir1/nested/deep.txt|dir2/two.txt")]
        [DataRow("**/empty/**", "")]
        [DataRow("dir*/", "")]
        [DataRow("**/", "")]
        [DataRow("dir*/.", "")]
        [DataRow("dir*/..", "")]
        public void Expand_Pattern_ReturnsExpectedFiles(string pattern, string expected)
        {
            this.AssertMatches(this.FullPath(pattern), expected.Split('|', StringSplitOptions.RemoveEmptyEntries));
        }

        [TestMethod]
        [DataRow("space file.txt", "space *.txt")]
        [DataRow("(notes){2}.txt", "(notes){2}*.txt")]
        [DataRow("file].txt", "file]*.txt")]
        [DataRow("file[.txt", "file[[]*.txt")]
        [DataRow("[abc].txt", "[[]abc].txt")]
        public void Expand_SpecialFileNames_PreservesLiteralCharacters(string name, string pattern)
        {
            this.CreateFile(name);
            this.AssertMatches(this.FullPath(pattern), name);
        }

        [TestMethod]
        public void Expand_EscapedDirectoryBrackets_SearchesMatchingDirectory()
        {
            this.CreateFile("[literal]/probe.txt");
            this.AssertMatches(this.FullPath("[[]literal]/*.txt"), "[literal]/probe.txt");
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow("[literal]")]
        [DataRow("[")]
        public void Expand_CurrentDirectoryWithBrackets_TreatsBaseAsLiteral(string directory)
        {
            this.CreateFile(directory + "/probe.txt");
            this.WithCurrentDirectory(this.FullPath(directory), () =>
            {
                foreach (string pattern in new[] { "probe.txt", "*", "*.txt", "./*.txt" })
                {
                    this.AssertMatches(pattern, directory + "/probe.txt");
                }
            });
        }

        [TestMethod]
        [DoNotParallelize]
        public void Expand_RelativePatterns_ResolveBaseWhenEnumerationBegins()
        {
            IEnumerable<FileSystemInfo> files = FileGlob.Expand("*.txt");
            IEnumerable<string> names = FileGlob.ExpandNames("*.txt");
            this.WithCurrentDirectory(this.root, () =>
            {
                CollectionAssert.AreEquivalent(new[] { this.FullPath("root.txt") }, files.Select(f => f.FullName).ToArray());
                CollectionAssert.AreEquivalent(new[] { this.FullPath("root.txt") }, names.ToArray());
                this.AssertMatches("dir*/*.txt", "dir1/one.txt", "dir2/two.txt");
                this.AssertMatches("**/deep.txt", "dir1/nested/deep.txt");
            });
        }

        [TestMethod]
        public void Expand_RootOnlyPatterns_ReturnNoFiles()
        {
            this.AssertMatches(Path.GetPathRoot(this.root)!);
            if (OperatingSystem.IsWindows())
            {
                this.AssertMatches(@"\\server\share");
                this.AssertMatches(@"\\server\share\");
                this.AssertMatches(@"\\?\UNC\server\share");
                this.AssertMatches(@"\\?\UNC\server\share\");
                this.AssertMatches(@"\\?\" + Path.GetPathRoot(this.root));
            }
        }

        [TestMethod]
        public void Expand_ParentNavigationAtRoot_StaysAtRoot()
        {
            int depth = 0;
            for (DirectoryInfo directory = new DirectoryInfo(this.root); directory.Parent is not null; directory = directory.Parent)
            {
                depth++;
            }

            string descend = Path.GetRelativePath(Path.GetPathRoot(this.root)!, this.root);
            string pattern = "dir*/" + string.Concat(Enumerable.Repeat("../", depth + 2)) + descend + "/root.txt";
            this.AssertMatches(this.FullPath(pattern), "root.txt");
        }

        [TestMethod]
        public void Expand_AlternateAndRepeatedSeparators_ResolveComponents()
        {
            string pattern = this.FullPath("dir*/nested/*.txt").Replace(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            this.AssertMatches(pattern, "dir1/nested/deep.txt");
            this.AssertMatches(this.FullPath("dir*//nested//*.txt"), "dir1/nested/deep.txt");
        }

        [TestMethod]
        [DoNotParallelize]
        public void Expand_WindowsRootAndDriveRelativePatterns_ResolveToFixture()
        {
            if (!OperatingSystem.IsWindows())
            {
                Assert.Inconclusive("Windows drive syntax requires Windows.");
                return;
            }

            this.WithCurrentDirectory(this.root, () =>
            {
                string drive = Path.GetPathRoot(this.root)![..2];
                this.AssertMatches(drive + "*.txt", "root.txt");
                this.AssertMatches(drive + "root.txt", "root.txt");
                this.AssertMatches(drive + "dir*/*.txt", "dir1/one.txt", "dir2/two.txt");
                this.AssertMatches(this.FullPath("*.txt")[2..], "root.txt");
            });
        }

        [TestMethod]
        public void Expand_WindowsExtendedPaths_ReturnExistingFiles()
        {
            if (!OperatingSystem.IsWindows())
            {
                Assert.Inconclusive("Extended Windows paths require Windows.");
                return;
            }

            foreach (string pattern in new[] { "root.txt", "*.txt", "dir*/*.txt", "**/deep.txt" })
            {
                string[] expected = FileGlob.ExpandNames(this.FullPath(pattern)).ToArray();
                string extended = @"\\?\" + this.FullPath(pattern);
                string[] names = FileGlob.ExpandNames(extended).Select(n => n[4..]).ToArray();
                FileSystemInfo[] files = FileGlob.Expand(extended).ToArray();
                CollectionAssert.AreEquivalent(expected, names);
                CollectionAssert.AreEquivalent(expected, files.Select(f => f.FullName[4..]).ToArray());
                Assert.IsTrue(files.All(f => f is FileInfo && f.Exists));
            }
        }

        [TestMethod]
        public void Expand_NullOrEmptyPattern_ThrowsImmediately()
        {
            Assert.ThrowsExactly<ArgumentNullException>(() => FileGlob.Expand(null!));
            Assert.ThrowsExactly<ArgumentNullException>(() => FileGlob.ExpandNames(null!));
            Assert.ThrowsExactly<ArgumentException>(() => FileGlob.Expand(""));
            Assert.ThrowsExactly<ArgumentException>(() => FileGlob.ExpandNames(""));
        }

        [TestMethod]
        [DataRow("[")]
        [DataRow("[]")]
        [DataRow("[^]")]
        [DataRow("[abc")]
        [DataRow("[z-a]")]
        [DataRow("[abc/*.txt")]
        [DataRow("missing/[abc")]
        public void Expand_InvalidCharacterGroups_ThrowDuringEnumeration(string pattern)
        {
            IEnumerable<FileSystemInfo> files = FileGlob.Expand(this.FullPath(pattern));
            IEnumerable<string> names = FileGlob.ExpandNames(this.FullPath(pattern));
            Assert.Throws<ArgumentException>(() => files.ToArray());
            Assert.Throws<ArgumentException>(() => names.ToArray());
        }

        [TestMethod]
        public void Expand_InvalidLiteralPath_PropagatesPathException()
        {
            Assert.Throws<ArgumentException>(() => FileGlob.Expand(this.FullPath("bad\0.txt")).ToArray());
            Assert.Throws<ArgumentException>(() => FileGlob.ExpandNames(this.FullPath("bad\0.txt")).ToArray());
        }

        [TestMethod]
        [DoNotParallelize]
        [DataRow(" ")]
        [DataRow("   ")]
        public void Expand_WhitespaceLiteral_PreservesPlatformPathSemantics(string pattern)
        {
            if (OperatingSystem.IsWindows())
            {
                Assert.Throws<ArgumentException>(() => FileGlob.Expand(pattern).ToArray());
                Assert.Throws<ArgumentException>(() => FileGlob.ExpandNames(pattern).ToArray());
            }
            else
            {
                this.CreateFile(pattern);
                this.WithCurrentDirectory(this.root, () => this.AssertMatches(pattern, pattern));
            }
        }

        [TestMethod]
        public void Expand_QueryBeforeDirectoryExists_DefersFileSystemAccess()
        {
            IEnumerable<FileSystemInfo> files = FileGlob.Expand(this.FullPath("later/*.txt"));
            IEnumerable<string> names = FileGlob.ExpandNames(this.FullPath("later/*.txt"));
            IEnumerable<string> literal = FileGlob.ExpandNames(this.FullPath("later/new.txt"));
            this.CreateFile("later/new.txt");
            CollectionAssert.AreEquivalent(new[] { this.FullPath("later/new.txt") }, files.Select(f => f.FullName).ToArray());
            CollectionAssert.AreEquivalent(new[] { this.FullPath("later/new.txt") }, names.ToArray());
            CollectionAssert.AreEquivalent(new[] { this.FullPath("later/new.txt") }, literal.ToArray());
        }

        [TestMethod]
        [DoNotParallelize]
        public void Expand_CurrentDirectoryChangesDuringEnumeration_KeepsResolvedBase()
        {
            this.WithCurrentDirectory(this.root, () =>
            {
                using IEnumerator<string> iterator = FileGlob.ExpandNames("dir*/*.txt").GetEnumerator();
                Assert.IsTrue(iterator.MoveNext());
                List<string> names = [iterator.Current];
                Directory.SetCurrentDirectory(this.FullPath("empty"));
                while (iterator.MoveNext())
                {
                    names.Add(iterator.Current);
                }

                CollectionAssert.AreEquivalent(new[] { this.FullPath("dir1/one.txt"), this.FullPath("dir2/two.txt") }, names);
            });
        }

        [TestMethod]
        public void Expand_RepeatedEnumeration_ObservesNewFiles()
        {
            this.CreateFile("repeat/one.txt");
            IEnumerable<FileSystemInfo> files = FileGlob.Expand(this.FullPath("repeat/*.txt"));
            IEnumerable<string> names = FileGlob.ExpandNames(this.FullPath("repeat/*.txt"));
            CollectionAssert.AreEquivalent(new[] { this.FullPath("repeat/one.txt") }, names.ToArray());
            CollectionAssert.AreEquivalent(new[] { this.FullPath("repeat/one.txt") }, files.Select(f => f.FullName).ToArray());
            this.CreateFile("repeat/two.txt");
            string[] expected = [this.FullPath("repeat/one.txt"), this.FullPath("repeat/two.txt")];
            CollectionAssert.AreEquivalent(expected, names.ToArray());
            CollectionAssert.AreEquivalent(expected, files.Select(f => f.FullName).ToArray());
        }

        [TestMethod]
        public void Expand_RecursiveTraversal_YieldsRootBeforeDiscoveringDescendants()
        {
            this.CreateFile("stream/first.txt");
            using IEnumerator<string> iterator = FileGlob.ExpandNames(this.FullPath("stream/**/*.txt")).GetEnumerator();
            Assert.IsTrue(iterator.MoveNext());
            Assert.AreEqual(this.FullPath("stream/first.txt"), iterator.Current);
            this.CreateFile("stream/new/deep.txt");
            List<string> rest = [];
            while (iterator.MoveNext())
            {
                rest.Add(iterator.Current);
            }

            CollectionAssert.AreEquivalent(new[] { this.FullPath("stream/new/deep.txt") }, rest);
        }

        [TestMethod]
        public void Expand_EarlyDisposal_ReleasesTraversalEnumerators()
        {
            this.CreateFile("stop/a/one.txt");
            this.CreateFile("stop/b/two.txt");
            using (IEnumerator<FileSystemInfo> iterator = FileGlob.Expand(this.FullPath("stop/**/*.txt")).GetEnumerator())
            {
                Assert.IsTrue(iterator.MoveNext());
                Assert.IsTrue(iterator.Current is FileInfo);
            }

            Directory.Delete(this.FullPath("stop"), true);
            this.AssertMatches(this.FullPath("stop/**/*.txt"));
        }

        [TestMethod]
        [Timeout(10000)]
        public void Expand_DeepTree_TraversesDirectoryLevelsIteratively()
        {
            string relative = "deep/" + string.Join('/', Enumerable.Repeat("d", 128)) + "/last.txt";
            this.CreateFile(relative);
            this.AssertMatches(this.FullPath("deep/**/last.txt"), relative);
        }

        [TestMethod]
        public void Expand_HiddenAndSystemEntries_AreNotImplicitlySkipped()
        {
            this.CreateFile("hidden/hidden.txt");
            string directory = this.FullPath("hidden");
            string file = this.FullPath("hidden/hidden.txt");
            FileAttributes directoryAttributes = File.GetAttributes(directory);
            FileAttributes fileAttributes = File.GetAttributes(file);
            try
            {
                File.SetAttributes(directory, directoryAttributes | FileAttributes.Hidden | FileAttributes.System);
                File.SetAttributes(file, fileAttributes | FileAttributes.Hidden | FileAttributes.System);
                this.AssertMatches(this.FullPath("**/hidden.txt"), "hidden/hidden.txt");
            }
            finally
            {
                File.SetAttributes(file, fileAttributes);
                File.SetAttributes(directory, directoryAttributes);
            }
        }

        [TestMethod]
        [Timeout(10000)]
        public void Expand_AncestorDirectoryLink_SkipsCycle()
        {
            this.CreateDirectoryLink("dir1/" + new string('l', 128), this.root);
            this.AssertMatches(this.FullPath("**/*.txt"), "root.txt", "dir1/one.txt", "dir1/nested/deep.txt", "dir2/two.txt");
            this.AssertMatches(this.FullPath("**"), "root.txt", "README.md", "dir1/one.txt", "dir1/nested/deep.txt", "dir2/two.txt");
        }

        [TestMethod]
        [Timeout(10000)]
        public void Expand_DirectoryLinks_SkipsDiscoveredButAllowsSelectedPaths()
        {
            this.CreateDirectoryLink("selected", this.FullPath("dir1"));
            this.AssertMatches(this.FullPath("**/deep.txt"), "dir1/nested/deep.txt");
            this.AssertMatches(this.FullPath("selected/**/*.txt"), "selected/one.txt", "selected/nested/deep.txt");
            this.AssertMatches(this.FullPath("select*/*.txt"), "selected/one.txt");
            this.AssertMatches(this.FullPath("**/selected/*.txt"), "selected/one.txt");
        }

        [TestMethod]
        [FileSymbolicLinkSupported]
        public void Expand_FileSymbolicLink_RemainsAFileMatch()
        {
            string link = this.FullPath("linked.txt");
            File.CreateSymbolicLink(link, this.FullPath("root.txt"));
            this.AssertMatches(this.FullPath("*.txt"), "root.txt", "linked.txt");
        }

        [TestMethod]
        public void Expand_InaccessibleDescendant_YieldsRootThenPropagatesAccessError()
        {
            if (!OperatingSystem.IsWindows())
            {
                Assert.Inconclusive("This access-denial fixture uses Windows ACLs.");
                return;
            }

            this.CreateFile("access/first.txt");
            this.CreateFile("access/locked/secret.txt");
            DirectoryInfo locked = new DirectoryInfo(this.FullPath("access/locked"));
            byte[] original = locked.GetAccessControl(AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
            DirectorySecurity denied = locked.GetAccessControl(AccessControlSections.Access);
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier user = identity.User!;
            denied.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.ListDirectory, AccessControlType.Deny));
            try
            {
                locked.SetAccessControl(denied);
                using IEnumerator<string> iterator = FileGlob.ExpandNames(this.FullPath("access/**/*.txt")).GetEnumerator();
                Assert.IsTrue(iterator.MoveNext());
                Assert.AreEqual(this.FullPath("access/first.txt"), iterator.Current);
                Assert.ThrowsExactly<UnauthorizedAccessException>(() =>
                {
                    while (iterator.MoveNext()) { }
                });
            }
            finally
            {
                DirectorySecurity restored = new DirectorySecurity();
                // Restore only the access ACL. Restoring audit information would
                // require SeSecurityPrivilege, which ordinary test accounts lack.
                restored.SetSecurityDescriptorBinaryForm(original, AccessControlSections.Access);
                locked.SetAccessControl(restored);
            }
        }

        private string FullPath(string relative)
        {
            return Path.Combine(this.root, relative.Replace('/', Path.DirectorySeparatorChar));
        }

        private void CreateFile(string relative)
        {
            string path = this.FullPath(relative);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, "fixture");
        }

        private void AssertMatches(string pattern, params string[] expected)
        {
            FileSystemInfo[] files = FileGlob.Expand(pattern).ToArray();
            string[] names = FileGlob.ExpandNames(pattern).ToArray();
            string[] paths = expected.Select(e => Path.GetFullPath(this.FullPath(e))).ToArray();
            CollectionAssert.AreEquivalent(paths, files.Select(f => f.FullName).ToArray());
            CollectionAssert.AreEquivalent(paths, names);
            Assert.IsTrue(files.All(f => f is FileInfo && f.Exists && Path.IsPathFullyQualified(f.FullName)));
            Assert.AreEqual(names.Length, names.Distinct().Count());
        }

        private void WithCurrentDirectory(string directory, Action action)
        {
            string original = Directory.GetCurrentDirectory();
            try
            {
                Directory.SetCurrentDirectory(directory);
                action();
            }
            finally
            {
                Directory.SetCurrentDirectory(original);
            }
        }

        private void CreateDirectoryLink(string relative, string target)
        {
            string link = this.FullPath(relative);
            if (OperatingSystem.IsWindows())
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("powershell.exe")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                };
                startInfo.ArgumentList.Add("-NoProfile");
                startInfo.ArgumentList.Add("-NonInteractive");
                startInfo.ArgumentList.Add("-Command");
                startInfo.ArgumentList.Add("$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction -Path '" + link.Replace("'", "''") + "' -Target '" + target.Replace("'", "''") + "' | Out-Null");
                using Process process = Process.Start(startInfo)!;
                if (!process.WaitForExit(10000))
                {
                    process.Kill(true);
                    Assert.Fail("Creating the junction timed out.");
                }

                Assert.AreEqual(0, process.ExitCode, process.StandardError.ReadToEnd());
            }
            else
            {
                Directory.CreateSymbolicLink(link, target);
            }

            this.links.Add(link);
        }
    }
}
