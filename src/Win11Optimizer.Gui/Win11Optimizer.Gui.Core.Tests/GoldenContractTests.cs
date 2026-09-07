using System.Collections.Generic;
using System.Linq;
using Win11Optimizer.Gui.Core;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// The committed bytes of P6-C1's contract, read by this shell.
    /// </summary>
    public class GoldenContractTests
    {
        [Fact]
        public void The_golden_file_is_four_lines()
        {
            Assert.Equal(4, Fixture.GoldenLines().Length);
        }

        [Fact]
        public void Every_line_carries_the_envelope_including_the_schema_version()
        {
            foreach (string line in Fixture.GoldenLines())
            {
                IDictionary<string, object> map = JsonBind.ParseObject(line);

                Assert.True(JsonBind.Has(map, "kind"));
                Assert.True(JsonBind.Has(map, "schemaVersion"));
                Assert.True(JsonBind.Has(map, "timestamp"));

                // schemaVersion is on EVERY record, not only the result. A
                // consumer holding one line has to be able to tell what it is
                // reading.
                Assert.Equal(1L, JsonBind.Int64(map, "schemaVersion", "schemaVersion"));
            }
        }

        [Fact]
        public void The_progress_line_binds_with_its_junk_phase_location_detail()
        {
            var progress = (ProgressRecord)ScanRecordReader.Read(Fixture.GoldenProgress());

            Assert.Equal(ScanContract.KindProgress, progress.Kind);
            Assert.Equal(ScanContract.PhaseJunkFiles, progress.Phase);
            Assert.Equal(3, progress.PhaseIndex);
            Assert.Equal(5, progress.PhaseCount);
            Assert.Equal("Measuring Fixture web cache.", progress.Message);

            // The junk phase is the only one whose work is a list a person can
            // watch go by, and this is the detail that lets a stopped run be
            // told apart from a working one.
            Assert.Equal("Fixture web cache", progress.Item);
            Assert.Equal(9, progress.ItemIndex);
            Assert.Equal(15, progress.ItemCount);

            Assert.Equal(3, progress.FindingCount);
            Assert.Equal(778, progress.InventoryCount);
        }

        [Fact]
        public void The_error_line_binds()
        {
            var error = (ScanErrorRecord)ScanRecordReader.Read(Fixture.GoldenError());

            Assert.Equal(ScanContract.KindError, error.Kind);
            Assert.Equal(ScanContract.PhaseJunkFiles, error.Phase);
            Assert.Equal("UnauthorizedAccessException", error.ExceptionType);
            Assert.Equal("Access to the path is denied.", error.Message);
        }

        [Fact]
        public void The_result_line_binds_to_four_scans_and_four_sections()
        {
            ResultRecord result = Result();

            Assert.Equal("FIXTURE-PC", result.MachineName);
            Assert.Equal("fixture", result.UserName);
            Assert.False(result.IsElevated);
            Assert.False(result.IsComplete);
            Assert.Equal(4, result.RowCount);

            Assert.Equal(
                new[] { "StartupItems", "UnusedApps", "OemBloatware", "JunkFiles" },
                result.Scan.Select(s => s.Detector).ToArray());

            Assert.Equal(
                new[] { "StartupItems", "InstalledApps", "JunkFiles", "Services" },
                result.Section.Select(s => s.Key).ToArray());
        }

        [Fact]
        public void The_partial_sections_are_named_rather_than_summarised()
        {
            // Four titles, so this field is a real array here. It is the same
            // field that collapses to a bare string at one element, which the
            // RefusedSourceName test below covers from the other side.
            Assert.Equal(
                new[] { "Startup items", "Installed apps", "Junk files", "Services" },
                Result().PartialSection.ToArray());
        }

        [Fact]
        public void All_four_source_statuses_are_read_and_only_two_make_a_scan_incomplete()
        {
            List<SourceRecord> sources =
                Result().Scan.SelectMany(s => s.Source).ToList();

            Assert.Contains(sources, s => s.Status == ScanContract.StatusSucceeded);
            Assert.Contains(sources, s => s.Status == ScanContract.StatusSkipped);
            Assert.Contains(sources, s => s.Status == ScanContract.StatusFailed);
            Assert.Contains(sources, s => s.Status == ScanContract.StatusRefused);

            foreach (SourceRecord source in sources)
            {
                bool expected =
                    source.Status == ScanContract.StatusSkipped ||
                    source.Status == ScanContract.StatusFailed;

                Assert.Equal(expected, source.MakesScanIncomplete);
            }
        }

        [Fact]
        public void A_refused_source_is_not_an_incomplete_one()
        {
            DetectorRecord unused =
                Result().Scan.Single(s => s.Detector == "UnusedApps");

            SourceRecord refused =
                unused.Source.Single(s => s.Status == ScanContract.StatusRefused);

            Assert.Equal("FileSystemLastAccess", refused.Name);
            Assert.False(refused.MakesScanIncomplete);

            // The reason is mandatory on every non-success status, and it says
            // this is a decision rather than a run condition.
            Assert.Equal(
                "Not used as a usage signal, by measurement rather than by assumption.",
                refused.Reason);
        }

        [Fact]
        public void A_succeeded_source_has_a_null_reason_rather_than_an_empty_one()
        {
            SourceRecord succeeded = Result().Scan
                .SelectMany(s => s.Source)
                .First(s => s.Status == ScanContract.StatusSucceeded);

            // The engine forces this to null rather than "" because callers
            // distinguish "there was no reason" from "the reason was blank".
            Assert.Null(succeeded.Reason);
        }

        [Fact]
        public void A_single_element_string_field_arrives_as_a_bare_string_and_still_reads_as_a_list()
        {
            ResultRecord result = Result();

            // RefusedSourceName: null at zero elements, a bare string at one.
            DetectorRecord startup = result.Scan.Single(s => s.Detector == "StartupItems");
            Assert.Empty(startup.RefusedSourceName);

            DetectorRecord unused = result.Scan.Single(s => s.Detector == "UnusedApps");
            Assert.Equal(new[] { "FileSystemLastAccess" }, unused.RefusedSourceName.ToArray());

            // Section Note: a bare string on Services, a real array on the
            // others. Both are lists of lines here.
            SectionRecord services = result.Section.Single(s => s.Key == "Services");
            Assert.Single(services.Note);
            Assert.StartsWith("This tool only ever changes a service startup type.", services.Note[0]);

            SectionRecord apps = result.Section.Single(s => s.Key == "InstalledApps");
            Assert.Equal(2, apps.Note.Count);

            // Row Evidence: a bare string on the OEM row, an array on the
            // startup row.
            RowRecord oem = apps.Row[0];
            Assert.Equal(
                new[] { "Matches curated known-bloatware list entry fixture-widget." },
                oem.Evidence.ToArray());

            RowRecord startupRow = result.Section.Single(s => s.Key == "StartupItems").Row[0];
            Assert.Equal(2, startupRow.Evidence.Count);
            Assert.Equal("Target file is missing.", startupRow.Evidence[0]);
        }

        [Fact]
        public void Cells_and_column_headers_stay_parallel_on_every_row()
        {
            foreach (SectionRecord section in Result().Section)
            {
                foreach (RowRecord row in section.Row)
                {
                    Assert.Equal(section.ColumnHeader.Count, row.Cell.Count);
                }
            }
        }

        [Fact]
        public void The_junk_row_carries_its_own_window_size_and_profile_split()
        {
            RowRecord junk = Result().Section.Single(s => s.Key == "JunkFiles").Row[0];

            Assert.True(junk.HasMinimumAgeDays);
            Assert.Equal(30, junk.MinimumAgeDays);

            Assert.True(junk.HasEligibleBytes);
            Assert.Equal(1220410048L, junk.EligibleBytes);

            Assert.True(junk.HasEligibleFileCount);
            Assert.Equal(1234, junk.EligibleFileCount);

            Assert.True(junk.HasIsSizeFloor);
            Assert.True(junk.IsSizeFloor);

            Assert.True(junk.HasLocationPath);
            Assert.Equal(2, junk.LocationPath.Count);

            Assert.True(junk.HasProfileBreakdown);
            Assert.Equal(2, junk.ProfileBreakdown.Count);
            Assert.Equal("Profile 1", junk.ProfileBreakdown[0].Profile);
            Assert.Equal(900, junk.ProfileBreakdown[0].FileCount);
            Assert.Equal(320410048L, junk.ProfileBreakdown[1].EligibleBytes);
        }

        [Fact]
        public void The_eligible_file_list_never_crosses_the_boundary()
        {
            // 773 records for one row on the machine this was measured on, and
            // 27,213 across the category. The payload carries the counts; the
            // list stays where it is.
            foreach (string line in Fixture.GoldenLines())
            {
                Assert.DoesNotContain("EligibleFile\"", line);
                Assert.DoesNotContain("RollbackData", line);
                Assert.DoesNotContain("\"Step\"", line);
            }
        }

        [Fact]
        public void The_plan_carries_its_preview_text_verbatim()
        {
            RowRecord row = Result().Section.Single(s => s.Key == "StartupItems").Row[0];

            Assert.True(row.HasPlan);
            Assert.NotNull(row.Plan);

            Assert.Equal(
                new[]
                {
                    @"Plan for HKCU\Run\Fixture",
                    "  This is what would happen. It is not a promise about what this PC will do afterwards."
                },
                row.Plan.PreviewText.ToArray());

            // Including the leading spaces on the second line: the engine wrote
            // them and the shell does not tidy them away.
            Assert.StartsWith("  ", row.Plan.PreviewText[1]);
        }

        [Fact]
        public void The_safety_label_is_read_and_never_re_derived()
        {
            ResultRecord result = Result();

            RowRecord review = result.Section.Single(s => s.Key == "StartupItems").Row[0];
            Assert.Equal(ScanContract.SafetyLabelReview, review.SafetyLabel);
            Assert.Equal("Heuristic", review.Confidence);

            RowRecord safe = result.Section.Single(s => s.Key == "InstalledApps").Row[0];
            Assert.Equal(ScanContract.SafetyLabelSafe, safe.SafetyLabel);

            // Nothing rule-shaped crosses the boundary, so there is nothing to
            // re-derive it from even if this shell wanted to.
            foreach (string line in Fixture.GoldenLines())
            {
                Assert.DoesNotContain("SafetyLabelRule", line);
                Assert.DoesNotContain("SafetyLabels", line);
            }
        }

        [Fact]
        public void The_total_line_is_present_only_where_there_are_rows_to_total()
        {
            ResultRecord result = Result();

            Assert.Equal(
                "The 1 rows above come to 1.14 GiB across 1,234 files on disk now.",
                result.Section.Single(s => s.Key == "JunkFiles").TotalLine);

            Assert.Null(result.Section.Single(s => s.Key == "StartupItems").TotalLine);
            Assert.Null(result.Section.Single(s => s.Key == "Services").TotalLine);
        }

        [Fact]
        public void The_awkward_characters_the_two_shells_disagree_about_survive_the_trip()
        {
            IDictionary<string, object> map =
                JsonBind.ParseObject(Fixture.GoldenProgressTorture());

            string text = JsonBind.String(map, "Text", "Text");

            Assert.Contains("quote:\"", text);
            Assert.Contains(@"backslash:\", text);
            Assert.Contains("slash:/", text);
            Assert.Contains("tab:\t", text);
            Assert.Contains("newline:\n", text);
            Assert.Contains("return:\r", text);

            // The four 5.1 escapes and the two above 0x7E. Written as C#
            // escapes so this source file stays ASCII, the same rule the
            // PowerShell fixture keeps.
            Assert.Contains("angles:<b>", text);
            Assert.Contains("ampersand:&", text);
            Assert.Contains("apostrophe:'", text);
            Assert.Contains("accented:\u00e9clair", text);
            Assert.Contains("cjk:\u4e2d", text);

            // Null and empty stay apart.
            Assert.Equal(string.Empty, JsonBind.String(map, "Empty", "Empty"));
            Assert.Null(JsonBind.String(map, "Nothing", "Nothing"));
            Assert.True(JsonBind.Has(map, "Nothing"));

            Assert.Equal(12345678901L, JsonBind.Int64(map, "Whole", "Whole"));
            Assert.Equal(-42L, JsonBind.Int64(map, "Negative", "Negative"));
            Assert.Equal(2.5, JsonBind.NullableDouble(map, "Fraction", "Fraction"));
            Assert.Equal(0.123457, JsonBind.NullableDouble(map, "Rounded", "Rounded"));
        }

        [Fact]
        public void A_progress_line_missing_a_required_field_is_refused_rather_than_defaulted()
        {
            // The first golden line is the WRITER's torture vector wrapped in a
            // progress envelope, not a sample of the stream: it carries none of
            // the nine fields New-OptimizerScanProgress guarantees. Refusing it
            // is the correct behaviour, and it is the same refusal a real
            // progress line would get if a field ever went missing.
            var ex = Assert.Throws<ScanProtocolException>(
                () => ScanRecordReader.Read(Fixture.GoldenProgressTorture()));

            Assert.Contains("PhaseIndex", ex.Message);
        }

        private static ResultRecord Result()
        {
            return (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
        }
    }
}
