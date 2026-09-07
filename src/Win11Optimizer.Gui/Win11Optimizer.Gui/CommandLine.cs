using System;
using System.Collections.Generic;

namespace Win11Optimizer.Gui
{
    /// <summary>
    /// What the shell was started with.
    /// </summary>
    public sealed class CommandLine
    {
        private CommandLine() { }

        /// <summary>An explicit engine module folder, or null to go and find one.</summary>
        public string EnginePath { get; private set; }

        /// <summary>
        /// Passes -SkipPlan through to the scan.
        /// </summary>
        /// <remarks>
        /// A launch flag rather than a decision taken here. Planning is most of
        /// what an elevated scan spends its time on -- P6-C1 measured 825
        /// seconds against 38.7 un-elevated -- and the cost of skipping it is
        /// that no card can say what would happen to a row. Which default is
        /// right is a question for the chunk that ships the plan preview; until
        /// then both can be measured on the same machine.
        /// </remarks>
        public bool SkipPlan { get; private set; }

        /// <summary>Anything that was not recognised, so it can be said rather than ignored.</summary>
        public IReadOnlyList<string> Unknown { get; private set; }

        public static CommandLine Parse(string[] args)
        {
            var result = new CommandLine();
            var unknown = new List<string>();

            for (int i = 0; args != null && i < args.Length; i++)
            {
                string arg = args[i];

                if (string.Equals(arg, "--skip-plan", StringComparison.OrdinalIgnoreCase))
                {
                    result.SkipPlan = true;
                }
                else if (string.Equals(arg, "--engine", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 < args.Length)
                    {
                        result.EnginePath = args[++i];
                    }
                    else
                    {
                        unknown.Add(arg + " (no path after it)");
                    }
                }
                else
                {
                    unknown.Add(arg);
                }
            }

            result.Unknown = unknown;
            return result;
        }
    }
}
