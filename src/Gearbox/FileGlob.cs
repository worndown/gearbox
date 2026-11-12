namespace Gearbox
{
    /// <summary>
    /// Performs file globbing with culture-invariant, case-insensitive wildcard matching.
    /// ? matches one character, * matches zero or more characters, and [...] matches
    /// a character set or range, optionally negated by a leading ^.
    /// A complete ** path component matches zero or more directory levels.
    /// </summary>
    /// <remarks>
    /// For example, src/*/*.cs searches one directory level, src/**/*.cs searches
    /// every level, and src/** returns all files below src, including files directly in src.
    /// Only files are returned; directory-only patterns, including those ending in a
    /// directory separator, return no matches. Use [[] to match a literal opening bracket.
    /// Recursive ** traversal skips directory symlinks and junctions it discovers,
    /// but explicitly selected linked paths and file symlinks remain searchable.
    /// Relative paths are resolved when enumeration begins. Filesystem access is lazy,
    /// missing paths return no matches, and enumeration/access errors propagate.
    /// Results have unique full paths; their order is unspecified.
    /// </remarks>
    public static class FileGlob
    {
        private static readonly char[] GlobCharacters = ['*', '?', '[', ']'];
        private static readonly char[] Separators = [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar];
        private static readonly StringComparer PathComparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;

        /// <summary>
        /// Lazily expands a file glob into FileInfo objects, exposed as FileSystemInfo.
        /// </summary>
        /// <param name="pattern">File path or globbing pattern to match.</param>
        /// <returns>Files with unique full paths that match the pattern.</returns>
        /// <exception cref="ArgumentNullException">The pattern is null.</exception>
        /// <exception cref="ArgumentException">The pattern is empty or has invalid path/glob syntax.</exception>
        /// <remarks>
        /// Null and empty arguments are rejected immediately. Path/glob parsing and
        /// filesystem enumeration occur when the returned sequence is enumerated.
        /// </remarks>
        public static IEnumerable<FileSystemInfo> Expand(string pattern)
        {
            ArgumentException.ThrowIfNullOrEmpty(pattern);
            return InternalExpand(pattern).DistinctBy(f => f.FullName, PathComparer);
        }

        /// <summary>
        /// Lazily expands a file glob into unique full file paths.
        /// </summary>
        /// <param name="pattern">File path or globbing pattern to match.</param>
        /// <returns>Full paths to matched files.</returns>
        /// <exception cref="ArgumentNullException">The pattern is null.</exception>
        /// <exception cref="ArgumentException">The pattern is empty or has invalid path/glob syntax.</exception>
        public static IEnumerable<string> ExpandNames(string pattern)
        {
            return Expand(pattern).Select(f => f.FullName);
        }

        private static IEnumerable<FileSystemInfo> InternalExpand(string pattern)
        {
            string root = Path.GetPathRoot(pattern) ?? string.Empty;
            if (Path.EndsInDirectorySeparator(pattern) || pattern.Length == root.Length)
            {
                yield break;
            }

            // Roots are literal, including the ? in an extended Windows path prefix.
            int firstGlob = pattern.AsSpan(root.Length).IndexOfAny(GlobCharacters);
            if (firstGlob < 0)
            {
                FileInfo file = new FileInfo(pattern);
                if (file.Exists)
                {
                    yield return file;
                }

                yield break;
            }

            // Resolve only the literal prefix. Normalizing the whole pattern would
            // collapse wildcard/.. before checking whether the wildcard matched.
            int prefixLength = Math.Max(root.Length, pattern.LastIndexOfAny(Separators, root.Length + firstGlob) + 1);
            DirectoryInfo baseDirectory = new DirectoryInfo(prefixLength == 0 ? "." : pattern[..prefixLength]);
            List<string> components = [];
            foreach (string component in pattern[prefixLength..].Split(Separators, StringSplitOptions.RemoveEmptyEntries))
            {
                if (component != "**" || components.LastOrDefault() != "**")
                {
                    components.Add(component);
                }
            }

            // A terminal globstar selects files at every directory level.
            if (components[^1] == "**")
            {
                components.Add("*");
            }

            Wildcard?[] matchers = components.Select(c => c == "**" ? null : new Wildcard(c)).ToArray();
            if (!baseDirectory.Exists)
            {
                yield break;
            }

            IEnumerable<DirectoryInfo> directories = [baseDirectory];
            for (int i = 0; i < components.Count - 1; i++)
            {
                directories = ExpandDirectories(directories, components[i], matchers[i])
                    .DistinctBy(d => d.FullName, PathComparer);
            }

            Wildcard filePattern = matchers[^1]!;
            foreach (DirectoryInfo directory in directories)
            {
                foreach (FileInfo file in directory.EnumerateFiles())
                {
                    if (filePattern.IsMatch(file.Name))
                    {
                        yield return file;
                    }
                }
            }
        }

        private static IEnumerable<DirectoryInfo> ExpandDirectories(
            IEnumerable<DirectoryInfo> directories, string component, Wildcard? matcher)
        {
            foreach (DirectoryInfo directory in directories)
            {
                switch (component)
                {
                    case "**":
                        foreach (DirectoryInfo descendant in GetDirectoriesAndSelf(directory))
                        {
                            yield return descendant;
                        }

                        break;
                    case ".":
                        yield return directory;
                        break;
                    case "..":
                        yield return directory.Parent ?? directory;
                        break;
                    default:
                        foreach (DirectoryInfo child in directory.EnumerateDirectories())
                        {
                            if (matcher!.IsMatch(child.Name))
                            {
                                yield return child;
                            }
                        }

                        break;
                }
            }
        }

        private static IEnumerable<DirectoryInfo> GetDirectoriesAndSelf(DirectoryInfo root)
        {
            yield return root;
            Stack<IEnumerator<DirectoryInfo>> stack = new Stack<IEnumerator<DirectoryInfo>>();
            try
            {
                stack.Push(root.EnumerateDirectories().GetEnumerator());
                while (stack.TryPeek(out IEnumerator<DirectoryInfo>? iterator))
                {
                    if (!iterator.MoveNext())
                    {
                        stack.Pop().Dispose();
                        continue;
                    }

                    DirectoryInfo child = iterator.Current;
                    if ((child.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        continue;
                    }

                    yield return child;
                    stack.Push(child.EnumerateDirectories().GetEnumerator());
                }
            }
            finally
            {
                foreach (IEnumerator<DirectoryInfo> iterator in stack)
                {
                    iterator.Dispose();
                }
            }
        }
    }
}
