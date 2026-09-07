using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// Where the committed contract bytes are, and how to build a payload that
    /// differs from them in exactly one way.
    /// </summary>
    internal static class Fixture
    {
        private const string GoldenRelativePath = @"tests\Fixtures\json-contract-golden.jsonl";

        /// <summary>
        /// The golden file P6-C1 committed: the same bytes both shells produce,
        /// proved by SHA-256 against a spawned second shell.
        /// </summary>
        /// <remarks>
        /// Reading THIS file rather than a copy is the point. It makes these
        /// tests a consumer-side contract test: if the engine's projection ever
        /// changes shape, the file changes, and these tests fail on the same
        /// commit as the PowerShell ones rather than in the field.
        /// </remarks>
        public static string[] GoldenLines()
        {
            string path = Path.Combine(RepoRoot(), GoldenRelativePath);
            if (!File.Exists(path))
            {
                throw new FileNotFoundException(
                    "The golden contract fixture was not found at " + path +
                    ". These tests read the committed bytes, not a copy of them.", path);
            }

            // Split on LF and drop the trailing empty: the file is LF-only by
            // construction and a reader that split on the platform newline
            // would quietly pass here and fail on a file with CRLF in it.
            string text = File.ReadAllText(path, Encoding.ASCII);
            string[] parts = text.Split('\n');

            var lines = new List<string>();
            foreach (string part in parts)
            {
                if (part.Length > 0)
                {
                    lines.Add(part);
                }
            }

            return lines.ToArray();
        }

        public static string GoldenProgressTorture() { return GoldenLines()[0]; }

        public static string GoldenProgress() { return GoldenLines()[1]; }

        public static string GoldenError() { return GoldenLines()[2]; }

        public static string GoldenResult() { return GoldenLines()[3]; }

        /// <summary>
        /// Walks up from the test assembly for the repository root. Nothing
        /// about this machine is compiled in.
        /// </summary>
        public static string RepoRoot()
        {
            string start = Path.GetDirectoryName(
                new Uri(typeof(Fixture).Assembly.CodeBase).LocalPath);

            var folder = new DirectoryInfo(start);
            while (folder != null)
            {
                if (File.Exists(Path.Combine(folder.FullName, GoldenRelativePath)))
                {
                    return folder.FullName;
                }

                folder = folder.Parent;
            }

            throw new DirectoryNotFoundException(
                "Could not find the repository root above " + start + ".");
        }

        /// <summary>A minimal, valid result line, for tests about everything except its content.</summary>
        public static string EmptyResult()
        {
            return
                "{\"kind\":\"result\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00.0000000Z\"," +
                "\"GeneratedUtc\":\"2026-09-06T12:00:00.0000000Z\",\"MachineName\":\"PC\"," +
                "\"UserName\":\"someone\",\"IsElevated\":false,\"IsComplete\":true," +
                "\"PartialSection\":null,\"RowCount\":0,\"ReceiptText\":null,\"Scan\":[],\"Section\":[]}";
        }

        public static string Progress(string phase, long phaseIndex)
        {
            return
                "{\"kind\":\"progress\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00.0000000Z\"," +
                "\"Phase\":\"" + phase + "\",\"PhaseIndex\":" + phaseIndex + ",\"PhaseCount\":5," +
                "\"Message\":\"Working.\",\"Item\":null,\"ItemIndex\":0,\"ItemCount\":0," +
                "\"FindingCount\":0,\"InventoryCount\":0}";
        }

        public static string Error(string phase, string exceptionType, string message)
        {
            return
                "{\"kind\":\"error\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00.0000000Z\"," +
                "\"Phase\":\"" + phase + "\",\"ExceptionType\":\"" + exceptionType + "\"," +
                "\"Message\":\"" + message + "\"}";
        }
    }
}
