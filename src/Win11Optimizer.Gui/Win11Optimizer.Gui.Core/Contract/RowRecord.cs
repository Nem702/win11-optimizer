using System.Collections.Generic;

namespace Win11Optimizer.Gui.Core.Contract
{
    /// <summary>
    /// One flagged row of one section.
    /// </summary>
    /// <remarks>
    /// <para>
    /// ABSENT IS NOT NULL, AND THAT IS THE WHOLE REASON THIS TYPE HAS Has*
    /// FLAGS. A row carries its category's own fields only where the detector
    /// really attached them. A row for an Appx package does not have a null age
    /// window -- it has no age window, and a null would be a placeholder for
    /// something that does not exist. A binder that defaulted a missing field
    /// to 0 would quietly turn "this does not apply" into "this is zero", which
    /// is the same shape as every other bug this project has hit: it returns
    /// something plausible instead of the truth, and raises nothing.
    /// </para>
    /// <para>
    /// So each optional field is a pair: Has* says whether the key was there at
    /// all, and the value says what it was. They are not interchangeable. A
    /// field can be present and null.
    /// </para>
    /// </remarks>
    public sealed class RowRecord
    {
        /// <summary>1-based WITHIN THE SECTION. Not unique across the screen.</summary>
        public long Number { get; internal set; }

        public string SectionKey { get; internal set; }
        public string DisplayName { get; internal set; }

        /// <summary>
        /// Not the same thing as SectionKey: the InstalledApps section holds
        /// both OemBloatware and UnusedApp rows, and the StartupItems and
        /// Services sections both come out of the one startup scan.
        /// </summary>
        public string Category { get; internal set; }

        /// <summary>
        /// Resolved by the engine, one of exactly two strings. The rule that
        /// produced it is a scriptblock that cannot cross a process boundary,
        /// and the payload deliberately does not carry enough pieces to
        /// re-derive it. This shell displays it and never recomputes it.
        /// </summary>
        public string SafetyLabel { get; internal set; }

        /// <summary>Pre-rendered display cells, positionally parallel to the section's ColumnHeader.</summary>
        public IReadOnlyList<string> Cell { get; internal set; }

        public string FindingId { get; internal set; }
        public string Confidence { get; internal set; }

        /// <summary>Nullable and never coerced -- see PlanRecord.RequiresConsent.</summary>
        public bool? RequiresConsent { get; internal set; }

        public string RemovalMethod { get; internal set; }
        public IReadOnlyList<string> Evidence { get; internal set; }

        // ---- OemBloatware ----------------------------------------------------
        public bool HasWhitelistEntryId { get; internal set; }
        public string WhitelistEntryId { get; internal set; }

        // ---- StartupItem and Service ----------------------------------------
        public bool HasMechanism { get; internal set; }
        public string Mechanism { get; internal set; }

        public bool HasFindingReason { get; internal set; }
        public string FindingReason { get; internal set; }

        public bool HasStartupEntryId { get; internal set; }
        public string StartupEntryId { get; internal set; }

        // ---- JunkFile --------------------------------------------------------
        public bool HasLocationId { get; internal set; }
        public string LocationId { get; internal set; }

        public bool HasLocationPath { get; internal set; }
        public IReadOnlyList<string> LocationPath { get; internal set; }

        public bool HasEligibleBytes { get; internal set; }
        public long? EligibleBytes { get; internal set; }

        public bool HasEligibleFileCount { get; internal set; }
        public long? EligibleFileCount { get; internal set; }

        public bool HasIsSizeFloor { get; internal set; }
        public bool? IsSizeFloor { get; internal set; }

        public bool HasMinimumAgeDays { get; internal set; }
        public long? MinimumAgeDays { get; internal set; }

        public bool HasProfileBreakdown { get; internal set; }
        public IReadOnlyList<ProfileBreakdownRecord> ProfileBreakdown { get; internal set; }

        // ---- the plan --------------------------------------------------------

        /// <summary>
        /// False when the scan was run with -SkipPlan, in which case no row has
        /// a plan and nothing is held back for being unsupported. It is also
        /// false when the key was absent for any other reason; Plan may be null
        /// while this is true, which is the engine saying the planner returned
        /// nothing for this row.
        /// </summary>
        public bool HasPlan { get; internal set; }

        public PlanRecord Plan { get; internal set; }
    }
}
