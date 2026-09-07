using System.Linq;
using Win11Optimizer.Gui.Core;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Json;
using Xunit;

namespace Win11Optimizer.Gui.Core.Tests
{
    /// <summary>
    /// What this shell will not read, and what it says when it will not.
    /// </summary>
    public class RefusalTests
    {
        [Fact]
        public void An_unknown_schema_version_is_refused_and_the_message_names_both_numbers()
        {
            string line = Fixture.EmptyResult().Replace("\"schemaVersion\":1", "\"schemaVersion\":2");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            // Naming both is the point: "unsupported version" tells the reader
            // nothing about which way the mismatch runs.
            Assert.Contains("version 1", ex.Message);
            Assert.Contains("version 2", ex.Message);
        }

        [Fact]
        public void The_version_is_checked_before_the_kind()
        {
            // A later schema may add a record kind. Refusing such a line for
            // its kind reports the symptom; refusing it for its version reports
            // the cause.
            string line =
                "{\"kind\":\"summary\",\"schemaVersion\":2,\"timestamp\":\"2026-09-06T12:00:00Z\"}";

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("version 2", ex.Message);
            Assert.DoesNotContain("summary", ex.Message);
        }

        [Fact]
        public void An_unknown_kind_is_refused_and_named()
        {
            string line =
                "{\"kind\":\"summary\",\"schemaVersion\":1,\"timestamp\":\"2026-09-06T12:00:00Z\"}";

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("'summary'", ex.Message);
            Assert.Contains("progress, result, error", ex.Message);
        }

        [Fact]
        public void A_line_that_is_not_json_is_refused_rather_than_skipped()
        {
            var ex = Assert.Throws<ScanProtocolException>(
                () => ScanRecordReader.Read("Get-Package : The term is not recognized."));

            Assert.Contains("not valid JSON", ex.Message);
        }

        [Fact]
        public void A_line_that_is_json_but_not_an_object_is_refused()
        {
            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read("[1,2,3]"));

            Assert.Contains("one complete object per line", ex.Message);
        }

        [Fact]
        public void An_unknown_source_status_is_refused_rather_than_treated_as_harmless()
        {
            // A fifth status arriving without a schema bump means this shell is
            // reading a stream it does not understand. Filing it under "not one
            // of the ones that matter" would silently drop a scan's
            // incompleteness.
            string line = Fixture.GoldenResult().Replace("\"Status\":\"Refused\"", "\"Status\":\"Deferred\"");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("'Deferred'", ex.Message);
            Assert.Contains("Succeeded, Skipped, Failed, Refused", ex.Message);
        }

        [Fact]
        public void A_microsoft_date_literal_is_refused_and_the_message_names_the_reason()
        {
            // This is what 5.1's own serializer emits for a [datetime]. The
            // engine writes ISO-8601 text on both shells precisely so it never
            // appears; if it does, the payload did not come from Review\Json.ps1.
            string line =
                "{\"kind\":\"progress\",\"schemaVersion\":1,\"timestamp\":\"\\/Date(1788696000000)\\/\"}";

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("Q29", ex.Message);
            Assert.Contains("ISO-8601", ex.Message);
        }

        [Fact]
        public void A_field_of_a_type_the_contract_does_not_use_is_refused_by_name()
        {
            string line = Fixture.EmptyResult().Replace("\"MachineName\":\"PC\"", "\"MachineName\":42");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("MachineName", ex.Message);
            Assert.Contains("should be text", ex.Message);
        }

        [Fact]
        public void Cells_that_do_not_line_up_with_their_column_headers_are_refused()
        {
            // They are read positionally. If they ever came apart, every cell
            // after the join would be shown under the wrong heading -- a wrong
            // answer that looks like a right one.
            string line = Fixture.GoldenResult().Replace(
                "\"ColumnHeader\":[\"#\",\"Service\",\"State\",\"Why flagged\",\"Safety\"]",
                "\"ColumnHeader\":[\"#\",\"Service\",\"State\",\"Safety\"]");

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("cells against", ex.Message);
            Assert.Contains("Services", ex.Message);
        }

        [Fact]
        public void A_missing_field_the_contract_guarantees_is_refused_rather_than_defaulted()
        {
            string line = Fixture.EmptyResult().Replace("\"IsComplete\":true,", string.Empty);

            var ex = Assert.Throws<ScanProtocolException>(() => ScanRecordReader.Read(line));

            Assert.Contains("IsComplete", ex.Message);
            Assert.Contains("was not there", ex.Message);
        }

        // ---- absent is not null ------------------------------------------------

        [Fact]
        public void A_category_field_the_row_does_not_have_reads_as_absent_not_as_zero()
        {
            var result = (ResultRecord)ScanRecordReader.Read(Fixture.GoldenResult());
            RowRecord appx = result.Section.Single(s => s.Key == "InstalledApps").Row[0];

            Assert.Equal("OemBloatware", appx.Category);

            // An Appx row does not have a null age window. It has no age
            // window. If this ever reads as 0 the screen would say the files
            // are older than zero days, which is a sentence about something
            // that does not exist.
            Assert.False(appx.HasMinimumAgeDays);
            Assert.Null(appx.MinimumAgeDays);

            Assert.False(appx.HasEligibleBytes);
            Assert.Null(appx.EligibleBytes);

            Assert.False(appx.HasIsSizeFloor);
            Assert.Null(appx.IsSizeFloor);

            Assert.False(appx.HasProfileBreakdown);
            Assert.Null(appx.ProfileBreakdown);

            // What it does have.
            Assert.True(appx.HasWhitelistEntryId);
            Assert.Equal("fixture-widget", appx.WhitelistEntryId);

            // And what belongs to a different category entirely.
            Assert.False(appx.HasMechanism);
            Assert.False(appx.HasStartupEntryId);
        }

        [Fact]
        public void Present_and_null_is_not_the_same_as_absent()
        {
            string line = Fixture.GoldenResult().Replace(
                "\"MinimumAgeDays\":30", "\"MinimumAgeDays\":null");

            var result = (ResultRecord)ScanRecordReader.Read(line);
            RowRecord junk = result.Section.Single(s => s.Key == "JunkFiles").Row[0];

            Assert.True(junk.HasMinimumAgeDays);
            Assert.Null(junk.MinimumAgeDays);
        }

        [Fact]
        public void A_non_boolean_requires_consent_reads_as_null_rather_than_as_false()
        {
            // The engine refuses to coerce this one, because the safety rule
            // fails closed on anything that is not a real boolean and repairing
            // it on the way through would hide what that clause exists to
            // catch. Nothing is repaired on this side either.
            string line = Fixture.GoldenResult().Replace(
                "\"RequiresConsent\":false,\"RemovalMethod\":\"RegistryRunKey\"",
                "\"RequiresConsent\":null,\"RemovalMethod\":\"RegistryRunKey\"");

            var result = (ResultRecord)ScanRecordReader.Read(line);
            RowRecord row = result.Section.Single(s => s.Key == "StartupItems").Row[0];

            Assert.Null(row.RequiresConsent);
            Assert.NotEqual(false, row.RequiresConsent);
        }

        [Fact]
        public void A_row_with_no_plan_reads_as_having_no_plan_rather_than_an_empty_one()
        {
            // What -SkipPlan produces: the Plan key is not written at all.
            string line = System.Text.RegularExpressions.Regex.Replace(
                Fixture.GoldenResult(), ",\"Plan\":\\{[^}]*\\}\\}", "}");

            var result = (ResultRecord)ScanRecordReader.Read(line);

            foreach (SectionRecord section in result.Section)
            {
                foreach (RowRecord row in section.Row)
                {
                    Assert.False(row.HasPlan);
                    Assert.Null(row.Plan);
                }
            }
        }
    }
}
