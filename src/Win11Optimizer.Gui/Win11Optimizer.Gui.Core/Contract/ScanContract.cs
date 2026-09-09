using System;
using System.Collections.Generic;

namespace Win11Optimizer.Gui.Core.Contract
{
    /// <summary>
    /// The protocol vocabulary, restated on the consumer side of the process
    /// boundary.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Restating it is unavoidable: a second process cannot call
    /// Get-OptimizerScanContract cheaply, and something has to know what a
    /// legal record looks like before it can refuse an illegal one. What
    /// matters is that these values are used to REFUSE what this shell does
    /// not recognise, never to fill in something the payload did not say.
    /// </para>
    /// <para>
    /// The restatement is not left to a comment to keep honest.
    /// tests\GuiShell.Tests.ps1 runs Get-OptimizerScanContract in the engine
    /// and asserts it against these constants, so the two lists cannot drift
    /// without a test going red.
    /// </para>
    /// </remarks>
    public static class ScanContract
    {
        /// <summary>The only schema version this shell can render.</summary>
        public const int SchemaVersion = 1;

        public const string KindProgress = "progress";
        public const string KindResult = "result";
        public const string KindError = "error";

        public const string PhaseStartupItems = "StartupItems";
        public const string PhaseInstalledApps = "InstalledApps";
        public const string PhaseJunkFiles = "JunkFiles";
        public const string PhasePlanning = "Planning";
        public const string PhaseAssembling = "Assembling";

        /// <summary>
        /// The phase the launcher reports when the engine module itself could
        /// not be imported. It is deliberately NOT one of the five published
        /// phases -- at that point nothing that knows about phases has loaded.
        /// App\Scan.ps1.
        /// </summary>
        public const string PhaseImport = "Import";

        public const string StatusSucceeded = "Succeeded";
        public const string StatusSkipped = "Skipped";
        public const string StatusFailed = "Failed";

        /// <summary>
        /// The fourth status, and the one a consumer gets wrong. Refused means
        /// this project has decided never to use a signal, on any machine, at
        /// any privilege level. It is a design decision, not a run condition,
        /// and it does NOT make a scan incomplete.
        /// </summary>
        public const string StatusRefused = "Refused";

        public const int ExitResultWritten = 0;
        public const int ExitNoResult = 1;

        public const string SectionStartupItems = "StartupItems";
        public const string SectionInstalledApps = "InstalledApps";
        public const string SectionJunkFiles = "JunkFiles";
        public const string SectionServices = "Services";

        /// <summary>The two safety labels the engine resolves. There is no third.</summary>
        public const string SafetyLabelSafe = "Safe to remove";
        public const string SafetyLabelReview = "Review needed";

        /// <summary>This inventory object became a Finding. Its row is in Row[], keyed by FindingId.</summary>
        public const string InventoryFlagged = "Flagged";

        /// <summary>
        /// A rule held this object back: a protected Windows namespace, or a
        /// class on the shared exclusion list. It was never offered, whatever
        /// else is true about it, and RuleId and RuleClass name the curated
        /// entry that did it.
        /// </summary>
        public const string InventoryHeldBack = "HeldBack";

        /// <summary>
        /// Inspected, no rule held it back, nothing flagged it. THIS IS A CLAIM
        /// AND NOT A DEFAULT: the engine decides it, and this shell must never
        /// arrive at it by failing to find one of the other two.
        /// </summary>
        public const string InventoryNotFlagged = "NotFlagged";

        private static readonly string[] KindList =
            { KindProgress, KindResult, KindError };

        private static readonly string[] PhaseList =
        {
            PhaseStartupItems, PhaseInstalledApps, PhaseJunkFiles,
            PhasePlanning, PhaseAssembling
        };

        private static readonly string[] SourceStatusList =
            { StatusSucceeded, StatusSkipped, StatusFailed, StatusRefused };

        /// <summary>
        /// The two statuses that make a scan incomplete. Refused is not one of
        /// them, and a consumer that treats all three non-success statuses the
        /// same reports a deliberate refusal as a failure.
        /// </summary>
        private static readonly string[] IncompleteStatusList =
            { StatusSkipped, StatusFailed };

        private static readonly string[] SectionKeyList =
        {
            SectionStartupItems, SectionInstalledApps,
            SectionJunkFiles, SectionServices
        };

        private static readonly string[] InventoryClassList =
            { InventoryFlagged, InventoryHeldBack, InventoryNotFlagged };

        public static IList<string> Kinds { get { return Copy(KindList); } }
        public static IList<string> Phases { get { return Copy(PhaseList); } }
        public static IList<string> SourceStatuses { get { return Copy(SourceStatusList); } }
        public static IList<string> IncompleteStatuses { get { return Copy(IncompleteStatusList); } }
        public static IList<string> SectionKeys { get { return Copy(SectionKeyList); } }
        public static IList<string> InventoryClasses { get { return Copy(InventoryClassList); } }

        public static bool IsKnownInventoryClass(string inventoryClass)
        {
            return IndexOf(InventoryClassList, inventoryClass) >= 0;
        }

        public static bool IsKnownKind(string kind)
        {
            return IndexOf(KindList, kind) >= 0;
        }

        /// <summary>
        /// True when a source status makes the scan that produced it
        /// incomplete. Refused returns false; an unknown status returns false
        /// as well, because guessing that an unrecognised status means failure
        /// is the same invention in the other direction. Unknown statuses are
        /// refused when the record is bound, not silently classified here.
        /// </summary>
        public static bool IsIncompleteStatus(string status)
        {
            return IndexOf(IncompleteStatusList, status) >= 0;
        }

        public static bool IsKnownSourceStatus(string status)
        {
            return IndexOf(SourceStatusList, status) >= 0;
        }

        /// <summary>The 1-based position of a phase, or 0 when it is not one of the five.</summary>
        public static int PhaseIndexOf(string phase)
        {
            return IndexOf(PhaseList, phase) + 1;
        }

        private static int IndexOf(string[] values, string value)
        {
            if (value == null)
            {
                return -1;
            }

            for (int i = 0; i < values.Length; i++)
            {
                if (string.Equals(values[i], value, StringComparison.Ordinal))
                {
                    return i;
                }
            }

            return -1;
        }

        // A copy, for the reason Get-RemovalContract hands out a copy of its
        // own table: a caller that can edit the published list can change what
        // every later caller believes the contract says.
        private static IList<string> Copy(string[] values)
        {
            return (string[])values.Clone();
        }
    }
}
