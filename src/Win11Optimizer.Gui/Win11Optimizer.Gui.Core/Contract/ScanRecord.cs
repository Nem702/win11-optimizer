using System.Collections.Generic;

namespace Win11Optimizer.Gui.Core.Contract
{
    /// <summary>
    /// One line of the protocol. Every record carries the envelope, because a
    /// consumer holding one line has to be able to tell what it is reading --
    /// schemaVersion is on every kind, not only on the result.
    /// </summary>
    public abstract class ScanRecord
    {
        /// <summary>progress, result or error.</summary>
        public string Kind { get; internal set; }

        public int SchemaVersion { get; internal set; }

        /// <summary>
        /// ISO-8601, as text. Deliberately not a DateTime: every timestamp in
        /// this contract is an explicit string on both shells (Q29), and
        /// parsing it back into a date here would reintroduce the ambiguity
        /// the engine went to some trouble to remove.
        /// </summary>
        public string Timestamp { get; internal set; }
    }

    /// <summary>
    /// A progress line. Every field is present on every one of them, whatever
    /// the phase -- the engine builds them that way on purpose, so a consumer
    /// never has to branch on a field that is sometimes absent.
    /// </summary>
    public sealed class ProgressRecord : ScanRecord
    {
        public string Phase { get; internal set; }

        /// <summary>1-based.</summary>
        public long PhaseIndex { get; internal set; }

        public long PhaseCount { get; internal set; }

        /// <summary>The engine's own sentence for this phase. Rendered verbatim.</summary>
        public string Message { get; internal set; }

        /// <summary>
        /// What it is on now, or null when the phase does not work through a
        /// list. Null and empty are kept apart by the engine: an empty string
        /// would read as "there was an item and it was blank".
        /// </summary>
        public string Item { get; internal set; }

        public long ItemIndex { get; internal set; }
        public long ItemCount { get; internal set; }

        /// <summary>
        /// Counts SO FAR, not totals. The phase that would make them totals has
        /// not finished. Nothing may present them as a total.
        /// </summary>
        public long FindingCount { get; internal set; }

        public long InventoryCount { get; internal set; }
    }

    /// <summary>
    /// The error line. It replaces the result; it never accompanies one.
    /// </summary>
    public sealed class ScanErrorRecord : ScanRecord
    {
        /// <summary>
        /// One of the five phases, or "Import" when the launcher could not load
        /// the engine module at all.
        /// </summary>
        public string Phase { get; internal set; }

        public string ExceptionType { get; internal set; }

        public string Message { get; internal set; }
    }

    /// <summary>One scan source, with its status and the reason for it.</summary>
    public sealed class SourceRecord
    {
        public string Name { get; internal set; }

        /// <summary>Succeeded, Skipped, Failed or Refused.</summary>
        public string Status { get; internal set; }

        /// <summary>
        /// Null for a Succeeded source, and a non-empty sentence for every
        /// other status. The engine forces the null rather than an empty
        /// string, and that distinction is preserved here.
        /// </summary>
        public string Reason { get; internal set; }

        public long? ItemCount { get; internal set; }
        public double? DurationSeconds { get; internal set; }

        /// <summary>
        /// True only for Skipped and Failed. Refused is a design decision and
        /// never makes a scan incomplete.
        /// </summary>
        public bool MakesScanIncomplete
        {
            get { return ScanContract.IsIncompleteStatus(Status); }
        }
    }

    /// <summary>One detector's run, and every source it read.</summary>
    public sealed class DetectorRecord
    {
        public string Detector { get; internal set; }
        public string Category { get; internal set; }

        /// <summary>ISO-8601 text, or "" when the engine had no value.</summary>
        public string StartedUtc { get; internal set; }

        public double? DurationSeconds { get; internal set; }
        public bool IsElevated { get; internal set; }
        public long? InventoryCount { get; internal set; }
        public long? FindingCount { get; internal set; }
        public bool IsComplete { get; internal set; }
        public string IncompleteReason { get; internal set; }
        public IReadOnlyList<string> RefusedSourceName { get; internal set; }
        public IReadOnlyList<SourceRecord> Source { get; internal set; }
    }
}
