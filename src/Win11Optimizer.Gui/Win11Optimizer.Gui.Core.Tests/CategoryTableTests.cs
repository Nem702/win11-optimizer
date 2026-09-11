using System;
using System.Linq;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Win11Optimizer.Gui.Core.View;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// The four category tables: which rows exist, which class each one is in,
    /// and what the three controls do.
    /// </summary>
    /// <remarks>
    /// ALL OF IT IS HERE AND NONE OF IT IS IN app.js. The testing line
    /// docs\handoff\21-gui-scaffold.md drew has not moved: anything that
    /// branches on what a value MEANS is on this side, rendering is judged by
    /// eye. Filtering, sorting, the class rule and the cross-reference are all
    /// judgements, so all four are tested here against the committed golden
    /// bytes rather than a copy of them.
    /// </remarks>
    public class CategoryTableTests
    {
        private static CategoryTableSet Set(string line)
        {
            return CategoryTableSet.Build((ResultRecord)ScanRecordReader.Read(line));
        }

        private static CategoryTableSet Golden()
        {
            return Set(Fixture.GoldenResult());
        }

        private static CategoryTable Table(string sectionKey)
        {
            return Golden().Find(sectionKey);
        }

        // ---- what exists ------------------------------------------------------

        [Fact]
        public void There_is_one_table_per_section_in_the_engines_own_order()
        {
            CategoryTableSet set = Golden();

            Assert.Equal(
                new[] { "StartupItems", "InstalledApps", "JunkFiles", "Services" },
                set.Table.Select(t => t.SectionKey).ToArray());

            Assert.Equal(
                new[] { "Startup items", "Installed apps", "Junk files", "Services" },
                set.Table.Select(t => t.Title).ToArray());
        }

        [Fact]
        public void Every_object_a_section_inspected_is_a_row_and_none_is_added()
        {
            foreach (CategoryTable table in Golden().Table)
            {
                Assert.Equal(table.InventoryCount, table.Row.Count);
                Assert.All(table.Row, r => Assert.Equal(table.Column.Count, r.Cell.Count));
            }
        }

        [Fact]
        public void The_headline_is_the_sections_own_sentences_verbatim()
        {
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            SectionRecord section = result.Section.Single(s => s.Key == "JunkFiles");

            Assert.Equal(section.Headline, Table("JunkFiles").Headline);
        }

        // ---- the four classes -------------------------------------------------

        [Fact]
        public void The_four_classes_are_four_and_protected_is_not_not_offered()
        {
            CategoryTable startup = Table("StartupItems");

            // Seven startup entries: one flagged run key, one flagged service
            // whose row is in the services section, one protected task, one
            // protected service, and three nothing was said about.
            Assert.Equal(2, startup.Row.Count(r => r.ClassIndex == CategoryTable.ClassIndexReview));
            Assert.Equal(2, startup.Row.Count(r => r.ClassIndex == CategoryTable.ClassIndexProtected));
            Assert.Equal(3, startup.Row.Count(r => r.ClassIndex == CategoryTable.ClassIndexNotOffered));

            // The point of the pair: they are different labels and different
            // indices, not one "not a decision" bucket.
            Assert.Equal("Protected",
                startup.Row.First(r => r.ClassIndex == CategoryTable.ClassIndexProtected).ClassLabel);
            Assert.Equal("Not offered",
                startup.Row.First(r => r.ClassIndex == CategoryTable.ClassIndexNotOffered).ClassLabel);
            Assert.NotEqual(CategoryTable.ClassProtected, CategoryTable.ClassNotOffered);
        }

        [Fact]
        public void A_finding_wears_the_engines_own_safety_label_verbatim()
        {
            CategoryTable apps = Table("InstalledApps");

            TableRow widget = apps.Row.Single(r => r.Cell[0] == "Fixture Widget");
            Assert.Equal(ScanContract.SafetyLabelSafe, widget.ClassLabel);
            Assert.Equal(CategoryTable.ClassIndexSafe, widget.ClassIndex);

            TableRow unused = apps.Row.Single(r => r.Cell[0] == "Fixture unused app");
            Assert.Equal(ScanContract.SafetyLabelReview, unused.ClassLabel);
            Assert.Equal(CategoryTable.ClassIndexReview, unused.ClassIndex);
        }

        [Fact]
        public void A_safety_label_this_shell_has_never_seen_is_drawn_as_needing_review()
        {
            // The same fail-closed rule the card keeps, and the same reason: a
            // label added to the engine later must never arrive on a table
            // already coloured as safe.
            string line = Fixture.GoldenResult().Replace(
                "\"SafetyLabel\":\"Safe to remove\"", "\"SafetyLabel\":\"Probably fine\"");

            TableRow widget = Set(line).Find("InstalledApps").Row.Single(r => r.Cell[0] == "Fixture Widget");

            Assert.Equal("Probably fine", widget.ClassLabel);
            Assert.Equal(CategoryTable.ClassIndexReview, widget.ClassIndex);
            Assert.NotEqual(CategoryTable.ClassIndexSafe, widget.ClassIndex);
        }

        // ---- the join ---------------------------------------------------------

        [Fact]
        public void The_join_is_on_finding_id_and_an_id_join_would_have_missed_it()
        {
            // The golden file carries this case on purpose: the unused-app
            // entry's Id is the package full name and its FindingId is the
            // package family name, because Find-UnusedApp rewrites one. Keyed
            // on Id, this row would have found no finding and been drawn as
            // something nothing was said about.
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            InventoryRecord entry = result.Section
                .Single(s => s.Key == "InstalledApps").Inventory
                .Single(i => i.DisplayName == "Fixture unused app");

            Assert.NotEqual(entry.Id, entry.FindingId);

            TableRow row = Table("InstalledApps").Row.Single(r => r.Cell[0] == "Fixture unused app");
            Assert.Equal(CategoryTable.ClassIndexReview, row.ClassIndex);
            Assert.Equal(ScanContract.SafetyLabelReview, row.ClassLabel);
        }

        [Fact]
        public void The_join_crosses_sections_because_a_services_row_is_not_in_the_startup_section()
        {
            // The flagged service is in the startup section's inventory and its
            // ROW is in the services section. A per-section join would have
            // left it with no label at all.
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            Assert.DoesNotContain(
                result.Section.Single(s => s.Key == "StartupItems").Row,
                r => r.FindingId == "FixtureSvc");

            TableRow row = Table("StartupItems").Row.Single(r => r.Cell[0] == "Fixture service");
            Assert.Equal(ScanContract.SafetyLabelReview, row.ClassLabel);
            Assert.Equal(0, Table("StartupItems").FlaggedWithNoRow);
        }

        [Fact]
        public void A_flagged_entry_with_no_row_anywhere_is_review_needed_and_is_counted()
        {
            // Fail closed in the second direction too. Nothing in the payload
            // says this object is safe, so nothing on the screen may.
            string line = Fixture.GoldenResult().Replace(
                "\"FindingId\":\"Fixture.Widget_8wekyb3d8bbwe\",\"Source\"",
                "\"FindingId\":\"Fixture.Vanished\",\"Source\"");

            CategoryTable apps = Set(line).Find("InstalledApps");
            TableRow widget = apps.Row.Single(r => r.Cell[0] == "Fixture Widget");

            Assert.Equal(CategoryTable.ClassIndexReview, widget.ClassIndex);
            Assert.Equal(ScanContract.SafetyLabelReview, widget.ClassLabel);
            Assert.Equal(1, apps.FlaggedWithNoRow);
        }

        [Fact]
        public void A_row_its_own_inventory_does_not_hold_is_named_and_is_not_invented_into_one()
        {
            // Elevated, the OEM scan reads AppxProvisionedPackage and the
            // unused-app scan does not, so a curated-list match can name a
            // package no classification holds. The table does not fabricate an
            // entry for it -- and it does not go quiet about it either.
            string line = Fixture.GoldenResult().Replace(
                "\"FindingId\":\"Fixture.Widget_8wekyb3d8bbwe\",\"Source\"",
                "\"FindingId\":\"Fixture.Vanished\",\"Source\"");

            CategoryTable apps = Set(line).Find("InstalledApps");

            Assert.Equal(5, apps.Row.Count);
            Assert.Equal(new[] { "Fixture Widget" }, apps.FindingNotInInventory.ToArray());
        }

        [Fact]
        public void Nothing_is_named_when_every_row_is_in_its_own_inventory()
        {
            Assert.All(Golden().Table, t => Assert.Empty(t.FindingNotInInventory));
            Assert.All(Golden().Table, t => Assert.Equal(0, t.FlaggedWithNoRow));
        }

        // ---- the service double-count -----------------------------------------

        [Fact]
        public void A_service_is_drawn_once_in_each_table_and_says_where_else_it_is()
        {
            CategoryTable startup = Table("StartupItems");
            CategoryTable services = Table("Services");

            Assert.Single(startup.Row, r => r.Cell[0] == "Fixture service");
            Assert.Single(services.Row, r => r.Cell[0] == "Fixture service");

            Assert.Equal(new[] { "Services" },
                startup.Row.Single(r => r.Cell[0] == "Fixture service").AlsoIn.ToArray());
            Assert.Equal(new[] { "Startup items" },
                services.Row.Single(r => r.Cell[0] == "Fixture service").AlsoIn.ToArray());
        }

        [Fact]
        public void Only_the_shared_objects_carry_a_cross_reference()
        {
            CategoryTable startup = Table("StartupItems");

            // Two of the seven startup entries are services; the five that are
            // not are in one table only and say nothing.
            Assert.Equal(2, startup.Row.Count(r => r.AlsoIn.Count > 0));
            Assert.All(Table("InstalledApps").Row, r => Assert.Empty(r.AlsoIn));
            Assert.All(Table("JunkFiles").Row, r => Assert.Empty(r.AlsoIn));
        }

        [Fact]
        public void Summing_the_four_inventories_double_counts_the_services()
        {
            // Stated as a test rather than as a comment, because it is the
            // reason no screen shows a cross-section total. On the fixture the
            // sum is 17 and the distinct objects are 15; the difference is
            // exactly the two services that are in both inventories.
            CategoryTableSet set = Golden();

            long summed = set.Table.Sum(t => t.InventoryCount);
            long shared = set.Table.Sum(t => t.Row.Count(r => r.AlsoIn.Count > 0)) / 2;

            Assert.Equal(17, summed);
            Assert.Equal(2, shared);
            Assert.Equal(15, summed - shared);
        }

        [Fact]
        public void Two_records_sharing_an_id_are_two_rows_and_are_not_cross_referenced()
        {
            // Id IS NOT UNIQUE. 39 of the 289 installed-app records on the
            // machine this was written on share one, in 17 groups -- Appx
            // framework packages under one package family name. Detail, the
            // package full name, is what separates them, and a table keyed on
            // Id alone would collapse them or mark each as "also in" the other.
            string line = Fixture.GoldenResult().Replace(
                "\"Id\":\"Fixture.Protected_8wekyb3d8bbwe\"",
                "\"Id\":\"Fixture.Widget_8wekyb3d8bbwe\"");

            CategoryTable apps = Set(line).Find("InstalledApps");

            Assert.Equal(5, apps.Row.Count);
            Assert.Equal(2, apps.Row.Count(r => r.Cell[1] == "Fixture.Widget_8wekyb3d8bbwe"));
            Assert.All(apps.Row, r => Assert.Empty(r.AlsoIn));
        }

        // ---- the cells --------------------------------------------------------

        [Fact]
        public void A_tri_state_is_three_different_words_and_a_missing_field_is_a_fourth()
        {
            CategoryTable startup = Table("StartupItems");
            const int target = 6;

            Assert.Equal("Missing", startup.Row.Single(r => r.Cell[0] == "Fixture startup item").Cell[target]);
            Assert.Equal("Present", startup.Row.Single(r => r.Cell[0] == "Fixture shortcut").Cell[target]);

            // Null is the engine saying it looked and could not tell. Drawn as
            // its own word, because rendering it as absent would manufacture an
            // orphan out of a permission the scan did not have.
            Assert.Equal("Not determined",
                startup.Row.Single(r => r.Cell[0] == "Fixture murky shortcut").Cell[target]);
        }

        [Fact]
        public void The_junk_tri_state_and_the_floor_qualifier_are_both_carried()
        {
            CategoryTable junk = Table("JunkFiles");
            TableRow cache = junk.Row.Single(r => r.Cell[0] == "Fixture web cache");
            TableRow temp = junk.Row.Single(r => r.Cell[0] == "System temporary files");

            Assert.Equal("Present", cache.Cell[3]);
            Assert.Equal("Not determined", temp.Cell[3]);

            // Grouped, and with the engine's own qualifier where the figure is a
            // floor. Dropping "or more" would report a floor as a total, which
            // is the under-report this project is built against.
            Assert.Equal("1,400,000,000 or more", cache.Cell[5]);
            Assert.Equal("1,220,410,048 or more", cache.Cell[7]);
            Assert.Equal("1,400", cache.Cell[4]);
            Assert.Equal("30 days", cache.Cell[8]);
        }

        [Fact]
        public void A_reason_is_the_engines_sentence_and_nothing_is_worded_here()
        {
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            InventoryRecord held = result.Section
                .Single(s => s.Key == "JunkFiles").Inventory
                .Single(i => i.IsHeldBack);

            TableRow row = Table("JunkFiles").Row.Single(r => r.Cell[1] == held.Id);

            // Character for character, including anything about its wording
            // this shell might have opinions on. The real payload's prefetch
            // reason is a lowercase fragment with no full stop and it is
            // rendered exactly as the engine wrote it.
            Assert.Equal(held.Reason, row.Cell[9]);
        }

        [Fact]
        public void A_field_a_category_does_not_carry_is_blank_and_never_a_value()
        {
            // The quiet Run key has no reason at all -- no rule fired and the
            // detector wrote no sentence. An empty cell, not a placeholder.
            TableRow quiet = Table("StartupItems").Row.Single(r => r.Cell[0] == "Fixture quiet entry");

            Assert.Equal(string.Empty, quiet.Cell[7]);
            Assert.Equal(string.Empty, quiet.Cell[4]);
        }

        // ---- the class filter -------------------------------------------------

        [Fact]
        public void The_class_filter_keeps_one_class_and_the_all_chip_clears_it()
        {
            CategoryTable startup = Table("StartupItems");

            startup.Apply(null, CategoryTable.ClassIndexProtected, CategoryTable.SortColumnNone, false);
            Assert.Equal(2, startup.Visible.Count);
            Assert.All(startup.Visible,
                i => Assert.Equal(CategoryTable.ClassIndexProtected, startup.Row[i].ClassIndex));

            startup.Apply(null, CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Equal(7, startup.Visible.Count);
        }

        [Fact]
        public void A_class_index_that_is_not_a_class_shows_everything_rather_than_nothing()
        {
            // A filter nobody asked for is worse than no filter: it hides rows
            // and says it is showing them all.
            CategoryTable startup = Table("StartupItems");

            startup.Apply(null, 9, CategoryTable.SortColumnNone, false);

            Assert.Equal(CategoryTable.ClassIndexAll, startup.ClassIndex);
            Assert.Equal(7, startup.Visible.Count);
        }

        [Fact]
        public void The_chip_counts_are_the_rows_in_each_class_and_they_add_up()
        {
            foreach (CategoryTable table in Golden().Table)
            {
                Assert.Equal(5, table.Chip.Count);
                Assert.Equal(CategoryTable.ClassIndexAll, table.Chip[0].ClassIndex);
                Assert.Equal(table.Row.Count, table.Chip[0].Count);
                Assert.Equal(table.Row.Count, table.Chip.Skip(1).Sum(c => c.Count));

                foreach (TableChip chip in table.Chip.Skip(1))
                {
                    Assert.Equal(
                        table.Row.Count(r => r.ClassIndex == chip.ClassIndex), chip.Count);
                }
            }
        }

        [Fact]
        public void The_two_finding_chips_are_labelled_with_the_engines_own_two_labels()
        {
            CategoryTable apps = Table("InstalledApps");

            Assert.Equal(ScanContract.SafetyLabelSafe, apps.Chip[1].Label);
            Assert.Equal(ScanContract.SafetyLabelReview, apps.Chip[2].Label);
            Assert.Equal(CategoryTable.ClassProtected, apps.Chip[3].Label);
            Assert.Equal(CategoryTable.ClassNotOffered, apps.Chip[4].Label);
        }

        // ---- the text filter ---------------------------------------------------

        [Fact]
        public void The_text_filter_searches_the_identity_and_ignores_case_and_space()
        {
            CategoryTable apps = Table("InstalledApps");

            apps.Apply("  FIXTURE WIDGET  ", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);

            // Trimmed, and given back as it was typed: a re-drawn table puts it
            // in the box, and a box that answered "FIXTURE WIDGET" with
            // "fixture widget" would look like the screen had rewritten it.
            Assert.Equal("FIXTURE WIDGET", apps.Query);
            Assert.Single(apps.Visible);
            Assert.Equal("Fixture Widget", apps.Row[apps.Visible[0]].Cell[0]);
        }

        [Fact]
        public void The_text_filter_reaches_the_id_and_the_detail_that_separates_two_of_them()
        {
            CategoryTable apps = Table("InstalledApps");

            // The package full name is only in Detail. Without it in the search
            // text there would be no way to pick out one of two records that
            // share an Id, which is the case the identity column exists for.
            apps.Apply("Fixture.Protected_2.0.0.0", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Single(apps.Visible);
            Assert.Equal("Fixture Security Suite", apps.Row[apps.Visible[0]].Cell[0]);

            apps.Apply("HKLM\\Fixture\\Uninstall", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Equal(2, apps.Visible.Count);
        }

        [Fact]
        public void The_text_filter_does_not_search_the_reason_or_the_publisher()
        {
            // It is a filter over the identity. Widening it to the reason would
            // make a search for a word that appears in one boilerplate sentence
            // return most of the table.
            CategoryTable apps = Table("InstalledApps");

            apps.Apply("absence of evidence", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Empty(apps.Visible);

            apps.Apply("CN=Fixture", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Empty(apps.Visible);
        }

        [Fact]
        public void An_empty_or_null_text_filter_shows_everything()
        {
            CategoryTable apps = Table("InstalledApps");

            apps.Apply("   ", CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Equal(5, apps.Visible.Count);

            apps.Apply(null, CategoryTable.ClassIndexAll, CategoryTable.SortColumnNone, false);
            Assert.Equal(5, apps.Visible.Count);
        }

        [Fact]
        public void The_two_filters_narrow_together()
        {
            CategoryTable startup = Table("StartupItems");

            startup.Apply("fixture", CategoryTable.ClassIndexProtected, CategoryTable.SortColumnNone, false);

            Assert.Equal(2, startup.Visible.Count);
            Assert.All(startup.Visible,
                i => Assert.Equal(CategoryTable.ClassIndexProtected, startup.Row[i].ClassIndex));
        }

        // ---- sorting -----------------------------------------------------------

        [Fact]
        public void Sorting_a_text_column_is_case_insensitive_and_leaves_the_rows_alone()
        {
            CategoryTable startup = Table("StartupItems");
            string[] before = startup.Row.Select(r => r.Cell[0]).ToArray();

            startup.Apply(null, CategoryTable.ClassIndexAll, 0, false);

            Assert.Equal(
                new[]
                {
                    "Fixture murky shortcut", "Fixture protected service", "Fixture protected task",
                    "Fixture quiet entry", "Fixture service", "Fixture shortcut", "Fixture startup item"
                },
                startup.Visible.Select(i => startup.Row[i].Cell[0]).ToArray());

            // Visible moves; Row never does.
            Assert.Equal(before, startup.Row.Select(r => r.Cell[0]).ToArray());
        }

        [Fact]
        public void A_row_with_nothing_in_the_sorted_column_goes_last_in_both_directions()
        {
            // Two of the seven startup entries have an empty publisher. An
            // empty cell is not a value that belongs at either end of an order,
            // and a screenful of blanks at the top hides the rows the sort was
            // asked for.
            CategoryTable startup = Table("StartupItems");
            const int publisher = 4;

            startup.Apply(null, CategoryTable.ClassIndexAll, publisher, false);
            string[] ascending = startup.Visible.Select(i => startup.Row[i].Cell[publisher]).ToArray();
            Assert.Equal(string.Empty, ascending[5]);
            Assert.Equal(string.Empty, ascending[6]);

            startup.Apply(null, CategoryTable.ClassIndexAll, publisher, true);
            string[] descending = startup.Visible.Select(i => startup.Row[i].Cell[publisher]).ToArray();
            Assert.Equal(string.Empty, descending[5]);
            Assert.Equal(string.Empty, descending[6]);

            // And the rows that do have one really did reverse.
            Assert.Equal(
                ascending.Take(5).Reverse().ToArray(), descending.Take(5).ToArray());
        }

        [Fact]
        public void A_numeric_column_is_sorted_on_the_number_and_not_on_the_rendered_text()
        {
            // "1,400,000,000" sorts below "52,428,800" as text. The fixture's
            // three junk locations are 1.4 GB, 52 MB and 0, and a text sort
            // would put the gigabyte in the middle.
            CategoryTable junk = Table("JunkFiles");
            const int onDisk = 5;

            junk.Apply(null, CategoryTable.ClassIndexAll, onDisk, false);

            // The smallest of the three is a floor of zero -- a folder under it
            // could not be listed -- and it keeps its qualifier while being
            // sorted on the number behind it.
            Assert.Equal(
                new[] { "0 or more", "52,428,800", "1,400,000,000 or more" },
                junk.Visible.Select(i => junk.Row[i].Cell[onDisk]).ToArray());
        }

        [Fact]
        public void Sorting_is_stable_so_a_tie_keeps_the_engines_order()
        {
            CategoryTable junk = Table("JunkFiles");
            const int olderThan = 8;

            // Two of the three carry a 7-day window. Tied, they stay in the
            // order the engine listed them.
            junk.Apply(null, CategoryTable.ClassIndexAll, olderThan, false);

            Assert.Equal(
                new[] { "Fixture prefetch folder", "System temporary files", "Fixture web cache" },
                junk.Visible.Select(i => junk.Row[i].Cell[0]).ToArray());
        }

        [Fact]
        public void Clicking_a_heading_sorts_it_and_clicking_it_again_reverses_it()
        {
            CategoryTable startup = Table("StartupItems");

            startup.ToggleSort(0);
            Assert.Equal(0, startup.SortColumn);
            Assert.False(startup.Descending);

            startup.ToggleSort(0);
            Assert.Equal(0, startup.SortColumn);
            Assert.True(startup.Descending);

            // A different heading starts again, ascending.
            startup.ToggleSort(4);
            Assert.Equal(4, startup.SortColumn);
            Assert.False(startup.Descending);
        }

        [Fact]
        public void A_column_with_no_order_and_a_column_that_is_not_there_are_both_ignored()
        {
            CategoryTable startup = Table("StartupItems");
            startup.ToggleSort(0);

            // The reason column has no order, and a click on it must not
            // silently become a sort on something else.
            Assert.False(startup.Column[7].IsSortable);
            startup.ToggleSort(7);
            Assert.Equal(0, startup.SortColumn);

            startup.ToggleSort(99);
            Assert.Equal(0, startup.SortColumn);

            startup.Apply(null, CategoryTable.ClassIndexAll, 7, false);
            Assert.Equal(CategoryTable.SortColumnNone, startup.SortColumn);
        }

        [Fact]
        public void Sorting_and_filtering_survive_each_other()
        {
            CategoryTable startup = Table("StartupItems");

            startup.ToggleSort(0);
            startup.Apply("fixture", CategoryTable.ClassIndexProtected, startup.SortColumn, startup.Descending);

            Assert.Equal(0, startup.SortColumn);
            Assert.Equal(
                new[] { "Fixture protected service", "Fixture protected task" },
                startup.Visible.Select(i => startup.Row[i].Cell[0]).ToArray());
        }

        [Fact]
        public void A_table_opens_unfiltered_in_the_engines_order()
        {
            foreach (CategoryTable table in Golden().Table)
            {
                Assert.Equal(string.Empty, table.Query);
                Assert.Equal(CategoryTable.ClassIndexAll, table.ClassIndex);
                Assert.Equal(CategoryTable.SortColumnNone, table.SortColumn);
                Assert.False(table.Descending);
                Assert.Equal(Enumerable.Range(0, table.Row.Count).ToArray(), table.Visible.ToArray());
            }
        }

        // ---- the columns --------------------------------------------------------

        [Fact]
        public void The_reason_column_is_the_last_one_and_is_the_only_one_with_no_order()
        {
            foreach (CategoryTable table in Golden().Table)
            {
                Assert.Equal("Why", table.Column[table.Column.Count - 1].Label);
                Assert.True(table.Column[table.Column.Count - 1].IsReason);
                Assert.Equal(1, table.Column.Count(c => !c.IsSortable));
            }
        }

        [Fact]
        public void Every_table_carries_an_identity_column_that_is_marked_as_one()
        {
            foreach (CategoryTable table in Golden().Table)
            {
                Assert.Equal("Identity", table.Column[1].Label);
                Assert.True(table.Column[1].IsIdentity);
            }

            // The installed-apps table has a second, because the package full
            // name is the field that separates two records sharing an Id.
            Assert.Equal(2, Table("InstalledApps").Column.Count(c => c.IsIdentity));
        }

        [Fact]
        public void Only_the_junk_table_has_numbers_in_it()
        {
            Assert.Equal(5, Table("JunkFiles").Column.Count(c => c.IsNumeric));
            Assert.Equal(0, Table("StartupItems").Column.Count(c => c.IsNumeric));
            Assert.Equal(0, Table("InstalledApps").Column.Count(c => c.IsNumeric));
            Assert.Equal(0, Table("Services").Column.Count(c => c.IsNumeric));
        }

        // ---- the rail ----------------------------------------------------------

        [Fact]
        public void The_rail_names_the_queue_the_four_tables_and_the_receipt()
        {
            DecisionsView view = DecisionsView.Build((ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult()));

            Assert.Equal(
                new[] { "decisions", "StartupItems", "InstalledApps", "JunkFiles", "Services", "receipt" },
                view.Rail.Select(r => r.Key).ToArray());

            Assert.Equal(view.Card.Count, view.Rail[0].Count);
            Assert.True(view.Rail[0].IsQueue);
        }

        [Fact]
        public void Every_rail_entry_that_is_not_the_receipt_leads_to_a_table_that_exists()
        {
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            DecisionsView view = DecisionsView.Build(result);
            CategoryTableSet tables = CategoryTableSet.Build(result);

            foreach (RailEntry entry in view.Rail)
            {
                if (entry.Key == "decisions" || entry.Key == "receipt")
                {
                    continue;
                }

                CategoryTable table = tables.Find(entry.Key);
                Assert.NotNull(table);
                Assert.Equal(table.Title, entry.Label);
                Assert.Equal(table.InventoryCount, entry.Count);
                Assert.True(entry.IsBuilt);
            }
        }

        [Fact]
        public void The_receipt_is_named_as_not_built_rather_than_left_off_or_shipped_dead()
        {
            DecisionsView view = DecisionsView.Build((ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult()));
            RailEntry receipt = view.Rail.Single(r => r.Key == "receipt");

            Assert.False(receipt.IsBuilt);
            Assert.Equal("Not built yet", receipt.NotBuiltNote);
            Assert.Equal(1, view.Rail.Count(r => !r.IsBuilt));
        }

        [Fact]
        public void A_rail_count_is_the_sections_own_and_carries_no_total_beside_it()
        {
            // There is no cross-section figure on this type at all, and that is
            // the point: the only honest one is not the sum, and the brief's
            // preference is not to show one.
            DecisionsView view = DecisionsView.Build((ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult()));

            Assert.Equal(new long[] { 7, 5, 3, 2 },
                view.Rail.Where(r => r.Key != "decisions" && r.Key != "receipt").Select(r => r.Count).ToArray());

            Assert.DoesNotContain(typeof(DecisionsView).GetProperties(),
                p => p.Name.IndexOf("Total", StringComparison.Ordinal) >= 0);
        }

        // ---- building it at all --------------------------------------------------

        [Fact]
        public void Building_from_nothing_is_refused_rather_than_answered_with_an_empty_screen()
        {
            Assert.Throws<ArgumentNullException>(() => CategoryTableSet.Build(null));
        }

        [Fact]
        public void A_section_with_no_inventory_is_an_empty_table_and_not_a_missing_one()
        {
            CategoryTableSet set = Set(Fixture.EmptyResult());
            Assert.Empty(set.Table);
            Assert.Null(set.Find("StartupItems"));
        }
    }
}
