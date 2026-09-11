using System;
using System.Collections.Generic;
using System.Globalization;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.View
{
    /// <summary>One column of a category table.</summary>
    /// <remarks>
    /// WHICH COLUMNS EXIST, AND WHICH OF THEM HAVE AN ORDER, IS DECIDED HERE
    /// AND NOT IN THE PAINTER. A column that carries a publisher can be sorted
    /// alphabetically; one that carries the engine's reason sentence cannot be
    /// sorted into anything meaningful, and offering the control anyway would
    /// be a control that does nothing useful.
    /// </remarks>
    public sealed class TableColumn
    {
        internal TableColumn() { }

        public string Label { get; internal set; }

        /// <summary>False for the reason column, which has no order.</summary>
        public bool IsSortable { get; internal set; }

        /// <summary>
        /// The engine's sentence about this object.
        /// </summary>
        /// <remarks>
        /// IT IS THE LAST COLUMN, AND THAT IS A TRADE RATHER THAN AN OVERSIGHT.
        /// These tables are wider than the window at 1180px, so one long column
        /// has to be the one you scroll sideways for, and it is this one rather
        /// than the identity: problem P1 is that two rows reading the same name
        /// were told apart by a part of the identity that had been cut off, so
        /// the identity is the column that has to be on screen. The cost is
        /// that a long reason still sets the height of its row while sitting
        /// off the right edge. Measured and written down in the report.
        /// </remarks>
        public bool IsReason { get; internal set; }

        /// <summary>Right-aligned and tabular. Sorted on the number, not on the rendered text.</summary>
        public bool IsNumeric { get; internal set; }

        /// <summary>
        /// An identity, which WRAPS RATHER THAN TRUNCATES. Two rows can carry
        /// the same display name and differ only in the part of the identity a
        /// truncating cell would cut off, so a table that shortens this column
        /// is worse than one that lets it run on to a second line.
        /// </summary>
        public bool IsIdentity { get; internal set; }
    }

    /// <summary>One object a section inspected, as a table row.</summary>
    public sealed class TableRow
    {
        internal TableRow() { }

        /// <summary>Parallel to the table's Column, and always the same length.</summary>
        public IReadOnlyList<string> Cell { get; internal set; }

        /// <summary>0 safe, 1 review, 2 protected, 3 not offered.</summary>
        public int ClassIndex { get; internal set; }

        /// <summary>
        /// For the two finding classes this is the ENGINE'S OWN LABEL, verbatim,
        /// whatever it says. For the other two it is the shell's word for a row
        /// that is not a decision -- the engine writes no label for those,
        /// because it never offered them.
        /// </summary>
        public string ClassLabel { get; internal set; }

        /// <summary>
        /// The titles of the other sections whose table draws this same object.
        /// A display-level cross-reference and nothing more: it does not hide
        /// the row, it is not a link, and no control in one table acts on
        /// another table's view of the object.
        /// </summary>
        public IReadOnlyList<string> AlsoIn { get; internal set; }

        /// <summary>Lower-cased identity text the text filter runs over. Not serialised.</summary>
        internal string MatchText { get; set; }

        /// <summary>Sort keys for the numeric columns, null elsewhere. Not serialised.</summary>
        internal long?[] Number { get; set; }
    }

    /// <summary>One filter chip: a class, and how many rows are in it.</summary>
    public sealed class TableChip
    {
        internal TableChip() { }

        public string Label { get; internal set; }

        /// <summary>-1 for the chip that clears the class filter.</summary>
        public int ClassIndex { get; internal set; }

        public long Count { get; internal set; }
    }

    /// <summary>
    /// One category table: everything a section inspected, and the controls
    /// that make several hundred rows of it usable.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THE FOUR CLASSES ARE TWO DIFFERENT KINDS OF THING. Safe to remove and
    /// Review needed are findings -- rows in the decision queue, wearing the
    /// label the engine resolved for them. Protected and Not offered are not
    /// findings at all, and they are DISTINCT FROM EACH OTHER on purpose: an
    /// object a rule held back and an object no rule mentioned are different
    /// answers, and a console that renders both as silence is one of the
    /// things this window exists to fix.
    /// </para>
    /// <para>
    /// THE JOIN FROM AN INVENTORY ENTRY TO ITS ROW IS ON FindingId AND NEVER ON
    /// Id. Find-UnusedApp rewrites an Appx Finding's Id to the package family
    /// name and Find-KnownBloatware folds several inventory records into one
    /// Finding, so an Id join would miss those and draw the application twice
    /// -- once as a finding and once as "nothing was said". It is also a join
    /// ACROSS THE WHOLE PAYLOAD rather than within the section: a service is in
    /// the startup section's inventory and its row is in the services section,
    /// and a per-section join would show it as an unlabelled finding.
    /// </para>
    /// </remarks>
    public sealed class CategoryTable
    {
        /// <summary>A rule held this object back. The shell's word: the engine never labelled it.</summary>
        public const string ClassProtected = "Protected";

        /// <summary>Inspected, nothing flagged it. Not the same answer as Protected.</summary>
        public const string ClassNotOffered = "Not offered";

        public const int ClassIndexSafe = 0;
        public const int ClassIndexReview = 1;
        public const int ClassIndexProtected = 2;
        public const int ClassIndexNotOffered = 3;

        /// <summary>Clears the class filter. Not a class.</summary>
        public const int ClassIndexAll = -1;

        /// <summary>Leaves the rows in the engine's own order. Not a column.</summary>
        public const int SortColumnNone = -1;

        private const string Present = "Present";
        private const string Missing = "Missing";
        private const string Undetermined = "Not determined";

        private CategoryTable() { }

        public string SectionKey { get; private set; }

        /// <summary>The section's title, the engine's.</summary>
        public string Title { get; private set; }

        /// <summary>The section's headline sentences, verbatim.</summary>
        public IReadOnlyList<string> Headline { get; private set; }

        public IReadOnlyList<TableColumn> Column { get; private set; }

        /// <summary>Every row, in the engine's order. Filtering and sorting move Visible, never this.</summary>
        public IReadOnlyList<TableRow> Row { get; private set; }

        public IReadOnlyList<TableChip> Chip { get; private set; }

        /// <summary>
        /// The section's own count of what it inspected. Equal to Row.Count --
        /// the binder refuses a payload where it is not -- and kept separately
        /// so the screen states the engine's number rather than its own tally
        /// of what it managed to draw.
        /// </summary>
        public long InventoryCount { get; private set; }

        /// <summary>
        /// Display names of this section's flagged rows that ITS INVENTORY DOES
        /// NOT HOLD. Empty on every un-elevated run measured so far. Elevated,
        /// the OEM scan also reads AppxProvisionedPackage while the unused-app
        /// scan does not, so a curated-list match can name a package that is in
        /// no classification and therefore in no inventory entry.
        /// </summary>
        /// <remarks>
        /// NO ROW IS INVENTED FOR ONE. The engine's own report is that such an
        /// object "belongs to no row here", and fabricating an inventory entry
        /// the engine did not write would be the shell composing a record. What
        /// the screen must not do is let it vanish -- so it is counted, named,
        /// and said out loud on the table.
        /// </remarks>
        public IReadOnlyList<string> FindingNotInInventory { get; private set; }

        /// <summary>
        /// Flagged entries whose FindingId names no row anywhere in the payload.
        /// They are drawn as Review needed, never as Safe to remove, for the
        /// reason every unknown label is: the fail-closed direction is the only
        /// safe one.
        /// </summary>
        public long FlaggedWithNoRow { get; private set; }

        // ---- the controls, and what they currently say -------------------------

        /// <summary>
        /// The text filter as it was typed, trimmed. It goes back to the page
        /// so a re-drawn table shows what is actually being filtered on, which
        /// is why it is not the lower-cased form the matching uses.
        /// </summary>
        public string Query { get; private set; }

        /// <summary>The lower-cased form the matching runs on. Not serialised.</summary>
        private string _needle = string.Empty;

        public int ClassIndex { get; private set; }
        public int SortColumn { get; private set; }
        public bool Descending { get; private set; }

        /// <summary>
        /// Indices into Row, filtered and ordered. THE ONLY THING THE PAINTER
        /// READS to decide what to draw and in what order.
        /// </summary>
        public IReadOnlyList<int> Visible { get; private set; }

        /// <summary>
        /// Applies the three controls and recomputes Visible. Every judgement
        /// in here -- what the text filter searches, which columns have an
        /// order, where a row with no value for the sorted column goes -- is on
        /// this side of the line on purpose.
        /// </summary>
        public void Apply(string query, int classIndex, int sortColumn, bool descending)
        {
            string typed = query == null ? string.Empty : query.Trim();
            string normalised = typed.ToLowerInvariant();

            if (classIndex < ClassIndexSafe || classIndex > ClassIndexNotOffered)
            {
                classIndex = ClassIndexAll;
            }

            if (sortColumn < 0 || sortColumn >= Column.Count || !Column[sortColumn].IsSortable)
            {
                sortColumn = SortColumnNone;
            }

            Query = typed;
            _needle = normalised;
            ClassIndex = classIndex;
            SortColumn = sortColumn;
            Descending = sortColumn == SortColumnNone ? false : descending;

            var visible = new List<int>();
            for (int i = 0; i < Row.Count; i++)
            {
                TableRow row = Row[i];

                if (classIndex != ClassIndexAll && row.ClassIndex != classIndex)
                {
                    continue;
                }

                if (_needle.Length > 0 &&
                    row.MatchText.IndexOf(_needle, StringComparison.Ordinal) < 0)
                {
                    continue;
                }

                visible.Add(i);
            }

            if (SortColumn != SortColumnNone)
            {
                int column = SortColumn;
                bool down = Descending;
                bool numeric = Column[column].IsNumeric;

                visible.Sort(delegate (int a, int b)
                {
                    int result = numeric
                        ? CompareNumber(Row[a].Number[column], Row[b].Number[column], down)
                        : CompareText(Row[a].Cell[column], Row[b].Cell[column], down);

                    // Stable, because List.Sort is not: two rows that tie on the
                    // sorted column stay in the engine's order rather than in
                    // whatever order the partitioning happened to leave them.
                    return result != 0 ? result : a - b;
                });
            }

            Visible = visible;
        }

        /// <summary>
        /// What a click on a column heading means: the same column again
        /// reverses it, a different one starts ascending.
        /// </summary>
        /// <remarks>
        /// A CONVENTION, AND IT IS STILL ON THIS SIDE OF THE LINE. The painter
        /// reports which heading was clicked and nothing else; working out what
        /// that does to the order is the sort control, and the whole of the
        /// sort control is tested here. A column with no order is ignored --
        /// the click does not silently become a sort on some other column.
        /// </remarks>
        public void ToggleSort(int column)
        {
            if (column < 0 || column >= Column.Count || !Column[column].IsSortable)
            {
                return;
            }

            Apply(Query, ClassIndex, column, column == SortColumn && !Descending);
        }

        /// <summary>
        /// A row with nothing in the sorted column goes LAST IN BOTH
        /// DIRECTIONS. Ninety-eight blank publishers at the top of an ascending
        /// sort hide the rows the sort was asked for, and an empty cell is not
        /// a value that belongs at either end of an order.
        /// </summary>
        private static int CompareText(string a, string b, bool descending)
        {
            bool emptyA = string.IsNullOrEmpty(a);
            bool emptyB = string.IsNullOrEmpty(b);

            if (emptyA || emptyB)
            {
                if (emptyA && emptyB)
                {
                    return 0;
                }

                return emptyA ? 1 : -1;
            }

            int result = string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
            return descending ? -result : result;
        }

        private static int CompareNumber(long? a, long? b, bool descending)
        {
            if (!a.HasValue || !b.HasValue)
            {
                if (!a.HasValue && !b.HasValue)
                {
                    return 0;
                }

                return a.HasValue ? -1 : 1;
            }

            int result = a.Value.CompareTo(b.Value);
            return descending ? -result : result;
        }

        // ---- building ----------------------------------------------------------

        internal static CategoryTable Build(
            SectionRecord section,
            IDictionary<string, RowRecord> rowByFindingId,
            IDictionary<string, List<string>> sectionTitleByObject)
        {
            var table = new CategoryTable
            {
                SectionKey = section.Key,
                Title = section.Title,
                Headline = section.Headline,
                InventoryCount = section.InventoryCount,
                Column = ColumnsFor(section.Key)
            };

            var rows = new List<TableRow>();
            var drawn = new HashSet<string>(StringComparer.Ordinal);
            long flaggedWithNoRow = 0;

            foreach (InventoryRecord entry in section.Inventory)
            {
                RowRecord row = null;
                if (entry.IsFlagged && entry.HasFindingId && entry.FindingId != null)
                {
                    rowByFindingId.TryGetValue(entry.FindingId, out row);
                    if (row == null)
                    {
                        flaggedWithNoRow++;
                    }

                    if (row != null)
                    {
                        drawn.Add(entry.FindingId);
                    }
                }
                else if (entry.IsFlagged)
                {
                    flaggedWithNoRow++;
                }

                rows.Add(BuildRow(table, section, entry, row, sectionTitleByObject));
            }

            // A flagged row of this section whose inventory does not hold it.
            // Named rather than drawn -- see FindingNotInInventory.
            var orphan = new List<string>();
            foreach (RowRecord row in section.Row)
            {
                if (row.FindingId != null && !drawn.Contains(row.FindingId))
                {
                    orphan.Add(row.DisplayName);
                }
            }

            table.Row = rows;
            table.FlaggedWithNoRow = flaggedWithNoRow;
            table.FindingNotInInventory = orphan;
            table.Chip = BuildChips(rows);

            table.Apply(null, ClassIndexAll, SortColumnNone, false);
            return table;
        }

        private static TableRow BuildRow(
            CategoryTable table,
            SectionRecord section,
            InventoryRecord entry,
            RowRecord row,
            IDictionary<string, List<string>> sectionTitleByObject)
        {
            var result = new TableRow();

            // THE CLASS RULE, AND IT FAILS CLOSED TWICE. An engine label this
            // shell has never seen is Review needed rather than Safe to remove,
            // which is the console's own rule kept identical; and a flagged
            // entry whose row cannot be found is Review needed as well, because
            // the alternative is calling something safe on the strength of not
            // having found the sentence that says so.
            if (entry.IsHeldBack)
            {
                result.ClassIndex = ClassIndexProtected;
                result.ClassLabel = ClassProtected;
            }
            else if (!entry.IsFlagged)
            {
                result.ClassIndex = ClassIndexNotOffered;
                result.ClassLabel = ClassNotOffered;
            }
            else if (row == null)
            {
                result.ClassIndex = ClassIndexReview;
                result.ClassLabel = ScanContract.SafetyLabelReview;
            }
            else
            {
                result.ClassLabel = row.SafetyLabel;
                result.ClassIndex =
                    string.Equals(row.SafetyLabel, ScanContract.SafetyLabelSafe, StringComparison.Ordinal)
                        ? ClassIndexSafe
                        : ClassIndexReview;
            }

            string detail = entry.HasDetail ? entry.Detail : null;
            result.AlsoIn = OtherSections(sectionTitleByObject, section.Title, entry, detail);

            var cell = new List<string>();
            var number = new List<long?>();
            FillCells(table.SectionKey, entry, cell, number);

            result.Cell = cell;
            result.Number = number.ToArray();

            // WHAT THE TEXT FILTER SEARCHES IS THE IDENTITY and not the whole
            // row. Detail is in it because it is the field that separates two
            // records sharing an Id -- 39 of the 289 installed-app records on
            // the machine this was written on, in 17 groups.
            result.MatchText = (
                Text(entry.DisplayName) + "\n" + Text(entry.Id) + "\n" + Text(detail)
            ).ToLowerInvariant();

            return result;
        }

        /// <summary>
        /// The cells, per category. The engine owns the table saying which
        /// category carries which field; this reads the Has* pairs rather than
        /// keeping a second copy of it, so a field a category does not have is
        /// an empty cell and never an invented value.
        /// </summary>
        private static void FillCells(
            string sectionKey, InventoryRecord entry, List<string> cell, List<long?> number)
        {
            Add(cell, number, Text(entry.DisplayName));
            Add(cell, number, Text(entry.Id));

            if (string.Equals(sectionKey, ScanContract.SectionJunkFiles, StringComparison.Ordinal))
            {
                Add(cell, number, entry.HasStatus ? Text(entry.Status) : string.Empty);
                Add(cell, number, Tri(entry.HasExists, entry.Exists));

                // The floor qualifier belongs to both figures: a folder that
                // could not be listed is missing from the total AND from the
                // eligible part of it.
                bool floor = entry.HasIsSizeFloor && entry.IsSizeFloor.HasValue && entry.IsSizeFloor.Value;

                AddNumber(cell, number, entry.HasFileCount, entry.FileCount, false);
                AddNumber(cell, number, entry.HasTotalBytes, entry.TotalBytes, floor);
                AddNumber(cell, number, entry.HasEligibleFileCount, entry.EligibleFileCount, false);
                AddNumber(cell, number, entry.HasEligibleBytes, entry.EligibleBytes, floor);
                AddDays(cell, number, entry.HasMinimumAgeDays, entry.MinimumAgeDays);
            }
            else if (string.Equals(sectionKey, ScanContract.SectionInstalledApps, StringComparison.Ordinal))
            {
                Add(cell, number, entry.HasDetail ? Text(entry.Detail) : string.Empty);
                Add(cell, number, entry.HasSource ? Text(entry.Source) : string.Empty);
                Add(cell, number, entry.HasState ? Text(entry.State) : string.Empty);
                Add(cell, number, entry.HasPublisher ? Text(entry.Publisher) : string.Empty);
            }
            else if (string.Equals(sectionKey, ScanContract.SectionServices, StringComparison.Ordinal))
            {
                Add(cell, number, entry.HasPublisher ? Text(entry.Publisher) : string.Empty);
                Add(cell, number, entry.HasEnabledState ? Text(entry.EnabledState) : string.Empty);
                Add(cell, number, Tri(entry.HasTargetExists, entry.TargetExists));
            }
            else
            {
                Add(cell, number, entry.HasMechanism ? Text(entry.Mechanism) : string.Empty);
                Add(cell, number, entry.HasScope ? Text(entry.Scope) : string.Empty);
                Add(cell, number, entry.HasPublisher ? Text(entry.Publisher) : string.Empty);
                Add(cell, number, entry.HasEnabledState ? Text(entry.EnabledState) : string.Empty);
                Add(cell, number, Tri(entry.HasTargetExists, entry.TargetExists));
            }

            Add(cell, number, entry.HasReason ? Text(entry.Reason) : string.Empty);
        }

        private static void Add(List<string> cell, List<long?> number, string text)
        {
            cell.Add(text);
            number.Add(null);
        }

        /// <summary>
        /// A count, grouped, with the engine's own qualifier where the figure is
        /// a floor. The unit is in the column heading rather than in every cell,
        /// and the SORT USES THE NUMBER -- a column sorted on "1,199,813,974"
        /// as text would put 9 bytes above a gigabyte.
        /// </summary>
        private static void AddNumber(
            List<string> cell, List<long?> number, bool has, long? value, bool isFloor)
        {
            if (!has || !value.HasValue)
            {
                cell.Add(string.Empty);
                number.Add(null);
                return;
            }

            string text = value.Value.ToString("N0", CultureInfo.InvariantCulture);
            cell.Add(isFloor ? text + " or more" : text);
            number.Add(value.Value);
        }

        private static void AddDays(List<string> cell, List<long?> number, bool has, long? value)
        {
            if (!has || !value.HasValue)
            {
                cell.Add(string.Empty);
                number.Add(null);
                return;
            }

            cell.Add(value.Value == 1
                ? "1 day"
                : value.Value.ToString("N0", CultureInfo.InvariantCulture) + " days");
            number.Add(value.Value);
        }

        /// <summary>
        /// A tri-state, as three different words. NULL IS NOT FALSE: the engine
        /// looked and could not tell, and a cell that rendered that as absent
        /// would manufacture an orphan out of a permission the scan did not
        /// have. A field the category does not carry at all is blank, which is
        /// a fourth thing again.
        /// </summary>
        private static string Tri(bool has, bool? value)
        {
            if (!has)
            {
                return string.Empty;
            }

            if (!value.HasValue)
            {
                return Undetermined;
            }

            return value.Value ? Present : Missing;
        }

        private static string Text(string value)
        {
            return value ?? string.Empty;
        }

        private static IReadOnlyList<TableColumn> ColumnsFor(string sectionKey)
        {
            // Name, then the identity, then the category's own fields, then the
            // reason. The first two are the same two on every table -- what is
            // it called, and which one is it -- and the painter puts the class
            // between them, so the three things a reader needs to tell one row
            // from another are the three that are on screen without scrolling.
            if (string.Equals(sectionKey, ScanContract.SectionJunkFiles, StringComparison.Ordinal))
            {
                return new[]
                {
                    Column_("Location", true, false, false),
                    Identity_("Identity"),
                    Column_("Status", true, false, false),
                    Column_("Folder", true, false, false),
                    Column_("Files", true, true, false),
                    Column_("On disk now (bytes)", true, true, false),
                    Column_("Eligible files", true, true, false),
                    Column_("Eligible (bytes)", true, true, false),
                    Column_("Older than", true, true, false),
                    Reason_()
                };
            }

            if (string.Equals(sectionKey, ScanContract.SectionInstalledApps, StringComparison.Ordinal))
            {
                return new[]
                {
                    Column_("Application", true, false, false),
                    Identity_("Identity"),
                    Identity_("Package or key"),
                    Column_("Found by", true, false, false),
                    Column_("Usage", true, false, false),
                    Column_("Publisher", true, false, false),
                    Reason_()
                };
            }

            if (string.Equals(sectionKey, ScanContract.SectionServices, StringComparison.Ordinal))
            {
                return new[]
                {
                    Column_("Service", true, false, false),
                    Identity_("Identity"),
                    Column_("Publisher", true, false, false),
                    Column_("State", true, false, false),
                    Column_("Target", true, false, false),
                    Reason_()
                };
            }

            return new[]
            {
                Column_("What", true, false, false),
                Identity_("Identity"),
                Column_("Starts via", true, false, false),
                Column_("Scope", true, false, false),
                Column_("Publisher", true, false, false),
                Column_("State", true, false, false),
                Column_("Target", true, false, false),
                Reason_()
            };
        }

        private static TableColumn Column_(string label, bool sortable, bool numeric, bool identity)
        {
            return new TableColumn
            {
                Label = label,
                IsSortable = sortable,
                IsNumeric = numeric,
                IsIdentity = identity
            };
        }

        private static TableColumn Identity_(string label)
        {
            return Column_(label, true, false, true);
        }

        /// <summary>
        /// The reason column. It is the one with no order: a list of sentences
        /// sorted alphabetically is not an answer to anything, and offering the
        /// control anyway would be a control that does nothing useful.
        /// </summary>
        private static TableColumn Reason_()
        {
            TableColumn column = Column_("Why", false, false, false);
            column.IsReason = true;
            return column;
        }

        private static IReadOnlyList<TableChip> BuildChips(IReadOnlyList<TableRow> rows)
        {
            var count = new long[4];
            foreach (TableRow row in rows)
            {
                count[row.ClassIndex]++;
            }

            return new[]
            {
                Chip_("All", ClassIndexAll, rows.Count),
                Chip_(ScanContract.SafetyLabelSafe, ClassIndexSafe, count[ClassIndexSafe]),
                Chip_(ScanContract.SafetyLabelReview, ClassIndexReview, count[ClassIndexReview]),
                Chip_(ClassProtected, ClassIndexProtected, count[ClassIndexProtected]),
                Chip_(ClassNotOffered, ClassIndexNotOffered, count[ClassIndexNotOffered])
            };
        }

        private static TableChip Chip_(string label, int classIndex, long count)
        {
            return new TableChip { Label = label, ClassIndex = classIndex, Count = count };
        }

        /// <summary>
        /// The other sections that draw this same object. Keyed on category, id
        /// AND the field that separates two records sharing an id, because an
        /// id on its own is not an identity here.
        /// </summary>
        private static IReadOnlyList<string> OtherSections(
            IDictionary<string, List<string>> sectionTitleByObject,
            string ownTitle,
            InventoryRecord entry,
            string detail)
        {
            List<string> titles;
            if (!sectionTitleByObject.TryGetValue(ObjectKey(entry, detail), out titles))
            {
                return new string[0];
            }

            var other = new List<string>();
            foreach (string title in titles)
            {
                if (!string.Equals(title, ownTitle, StringComparison.Ordinal) && !other.Contains(title))
                {
                    other.Add(title);
                }
            }

            return other;
        }

        internal static string ObjectKey(InventoryRecord entry, string detail)
        {
            // A separator no identity, category or package name can contain, so two
            // different triples cannot run together into one key.
            return Text(entry.Category) + "\u0001" + Text(entry.Id) + "\u0001" + Text(detail);
        }
    }

    /// <summary>
    /// The four category tables.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A SERVICE IS IN TWO INVENTORIES AND IS DRAWN ONCE IN EACH TABLE. The
    /// startup scan's own structure is that the services are among the things
    /// that start with the PC, so the startup section's inventory holds all 92
    /// of them and the services section holds the same 92 again. Ninety-two of
    /// the 548 entries on the machine this was written on are that one overlap.
    /// </para>
    /// <para>
    /// GROUPED FOR DISPLAY, NEVER MERGED. Each table draws its own section's
    /// inventory; a row that another table also draws says so and does nothing
    /// else. No control in one table acts on the other's view of the same
    /// object, because one object has one state and neither table may imply
    /// two.
    /// </para>
    /// <para>
    /// AND NOTHING HERE SUMS THE SECTION INVENTORIES. 548 is not the number of
    /// things inspected on this machine -- it counts 92 services twice. No
    /// screen shows a cross-section total, which is why this type publishes
    /// none.
    /// </para>
    /// </remarks>
    public sealed class CategoryTableSet
    {
        private CategoryTableSet() { }

        /// <summary>The four tables, in the engine's section order.</summary>
        public IReadOnlyList<CategoryTable> Table { get; private set; }

        public static CategoryTableSet Build(ResultRecord result)
        {
            if (result == null)
            {
                throw new ArgumentNullException("result");
            }

            // Every row in the payload, by FindingId. Across sections, because
            // a flagged entry in the startup inventory names a row in the
            // services section.
            var rowByFindingId = new Dictionary<string, RowRecord>(StringComparer.Ordinal);
            foreach (SectionRecord section in result.Section)
            {
                foreach (RowRecord row in section.Row)
                {
                    if (row.FindingId != null && !rowByFindingId.ContainsKey(row.FindingId))
                    {
                        rowByFindingId[row.FindingId] = row;
                    }
                }
            }

            var sectionTitleByObject = new Dictionary<string, List<string>>(StringComparer.Ordinal);
            foreach (SectionRecord section in result.Section)
            {
                foreach (InventoryRecord entry in section.Inventory)
                {
                    string key = CategoryTable.ObjectKey(entry, entry.HasDetail ? entry.Detail : null);

                    List<string> titles;
                    if (!sectionTitleByObject.TryGetValue(key, out titles))
                    {
                        titles = new List<string>();
                        sectionTitleByObject[key] = titles;
                    }

                    if (!titles.Contains(section.Title))
                    {
                        titles.Add(section.Title);
                    }
                }
            }

            var tables = new List<CategoryTable>();
            foreach (SectionRecord section in result.Section)
            {
                tables.Add(CategoryTable.Build(section, rowByFindingId, sectionTitleByObject));
            }

            return new CategoryTableSet { Table = tables };
        }

        /// <summary>The table for a section key, or null.</summary>
        public CategoryTable Find(string sectionKey)
        {
            foreach (CategoryTable table in Table)
            {
                if (string.Equals(table.SectionKey, sectionKey, StringComparison.Ordinal))
                {
                    return table;
                }
            }

            return null;
        }
    }
}
