using System.Collections.Generic;
using System.Globalization;
using Win11Optimizer.Gui.Core.Contract;

namespace Win11Optimizer.Gui.Core.Json
{
    /// <summary>
    /// One protocol line to one typed record, or a refusal.
    /// </summary>
    /// <remarks>
    /// The envelope is merged flat beside the payload rather than nested, so
    /// everything is read out of the one dictionary.
    /// </remarks>
    public static class ScanRecordReader
    {
        /// <summary>
        /// Reads one line. Never returns null and never returns a partly-bound
        /// record: it either produces a record it fully understood, or throws.
        /// </summary>
        public static ScanRecord Read(string line)
        {
            IDictionary<string, object> map = JsonBind.ParseObject(line);

            string kind = JsonBind.String(map, "kind", "kind");
            if (string.IsNullOrEmpty(kind))
            {
                throw new ScanProtocolException(
                    "A line of the scan output has no 'kind', so there is no way to tell what it is.");
            }

            // THE VERSION IS CHECKED BEFORE THE KIND, and the order is the
            // point. A later schema may add a record kind; refusing that line
            // for its kind would report the symptom, and refusing it for its
            // version reports the cause. A shell that silently rendered an
            // unrecognised payload is the version of this that fails in the
            // field.
            long version = JsonBind.Int64(map, "schemaVersion", "schemaVersion");
            if (version != ScanContract.SchemaVersion)
            {
                throw new ScanProtocolException(
                    "This shell understands scan schema version " +
                    ScanContract.SchemaVersion.ToString(CultureInfo.InvariantCulture) +
                    ", and the scan produced version " +
                    version.ToString(CultureInfo.InvariantCulture) +
                    ". Nothing is shown, because rendering a payload whose shape is not " +
                    "the one this shell was built against would report something that was " +
                    "never measured.");
            }

            if (!ScanContract.IsKnownKind(kind))
            {
                throw new ScanProtocolException(
                    "A line of the scan output is of kind '" + kind +
                    "', which this shell does not know. The kinds it knows are " +
                    string.Join(", ", (string[])ScanContract.Kinds) + ".");
            }

            string timestamp = JsonBind.String(map, "timestamp", "timestamp");

            if (kind == ScanContract.KindProgress)
            {
                return ReadProgress(map, kind, (int)version, timestamp);
            }

            if (kind == ScanContract.KindError)
            {
                return ReadError(map, kind, (int)version, timestamp);
            }

            return ReadResult(map, kind, (int)version, timestamp);
        }

        private static ProgressRecord ReadProgress(
            IDictionary<string, object> map, string kind, int version, string timestamp)
        {
            return new ProgressRecord
            {
                Kind = kind,
                SchemaVersion = version,
                Timestamp = timestamp,
                Phase = JsonBind.String(map, "Phase", "Phase"),
                PhaseIndex = JsonBind.Int64(map, "PhaseIndex", "PhaseIndex"),
                PhaseCount = JsonBind.Int64(map, "PhaseCount", "PhaseCount"),
                Message = JsonBind.String(map, "Message", "Message"),
                Item = JsonBind.String(map, "Item", "Item"),
                ItemIndex = JsonBind.Int64(map, "ItemIndex", "ItemIndex"),
                ItemCount = JsonBind.Int64(map, "ItemCount", "ItemCount"),
                FindingCount = JsonBind.Int64(map, "FindingCount", "FindingCount"),
                InventoryCount = JsonBind.Int64(map, "InventoryCount", "InventoryCount")
            };
        }

        private static ScanErrorRecord ReadError(
            IDictionary<string, object> map, string kind, int version, string timestamp)
        {
            return new ScanErrorRecord
            {
                Kind = kind,
                SchemaVersion = version,
                Timestamp = timestamp,
                Phase = JsonBind.String(map, "Phase", "Phase"),
                ExceptionType = JsonBind.String(map, "ExceptionType", "ExceptionType"),
                Message = JsonBind.String(map, "Message", "Message")
            };
        }

        private static ResultRecord ReadResult(
            IDictionary<string, object> map, string kind, int version, string timestamp)
        {
            var scans = new List<DetectorRecord>();
            foreach (var scan in JsonBind.ObjectList(map, "Scan", "Scan"))
            {
                scans.Add(ReadDetector(scan));
            }

            var sections = new List<SectionRecord>();
            foreach (var section in JsonBind.ObjectList(map, "Section", "Section"))
            {
                sections.Add(ReadSection(section));
            }

            return new ResultRecord
            {
                Kind = kind,
                SchemaVersion = version,
                Timestamp = timestamp,
                GeneratedUtc = JsonBind.String(map, "GeneratedUtc", "GeneratedUtc"),
                MachineName = JsonBind.String(map, "MachineName", "MachineName"),
                UserName = JsonBind.String(map, "UserName", "UserName"),
                IsElevated = JsonBind.Bool(map, "IsElevated", "IsElevated"),
                IsComplete = JsonBind.Bool(map, "IsComplete", "IsComplete"),
                PartialSection = JsonBind.StringList(map, "PartialSection", "PartialSection"),
                RowCount = JsonBind.NullableInt64(map, "RowCount", "RowCount"),
                ReceiptText = JsonBind.StringList(map, "ReceiptText", "ReceiptText"),
                Scan = scans,
                Section = sections
            };
        }

        private static DetectorRecord ReadDetector(IDictionary<string, object> map)
        {
            string detector = JsonBind.String(map, "Detector", "Scan.Detector");
            string prefix = "Scan[" + (detector ?? "?") + "].";

            var sources = new List<SourceRecord>();
            foreach (var source in JsonBind.ObjectList(map, "Source", prefix + "Source"))
            {
                sources.Add(ReadSource(source, prefix));
            }

            return new DetectorRecord
            {
                Detector = detector,
                Category = JsonBind.String(map, "Category", prefix + "Category"),
                StartedUtc = JsonBind.String(map, "StartedUtc", prefix + "StartedUtc"),
                DurationSeconds = JsonBind.NullableDouble(map, "DurationSeconds", prefix + "DurationSeconds"),
                IsElevated = JsonBind.Bool(map, "IsElevated", prefix + "IsElevated"),
                InventoryCount = JsonBind.NullableInt64(map, "InventoryCount", prefix + "InventoryCount"),
                FindingCount = JsonBind.NullableInt64(map, "FindingCount", prefix + "FindingCount"),
                IsComplete = JsonBind.Bool(map, "IsComplete", prefix + "IsComplete"),
                IncompleteReason = JsonBind.String(map, "IncompleteReason", prefix + "IncompleteReason"),
                RefusedSourceName = JsonBind.StringList(map, "RefusedSourceName", prefix + "RefusedSourceName"),
                Source = sources
            };
        }

        private static SourceRecord ReadSource(IDictionary<string, object> map, string prefix)
        {
            string name = JsonBind.String(map, "Name", prefix + "Source.Name");
            string path = prefix + "Source[" + (name ?? "?") + "].";
            string status = JsonBind.String(map, "Status", path + "Status");

            // An unrecognised status is refused rather than filed under
            // "not one of the ones that matter". Get-OptimizerScanContract
            // publishes four, and a fifth arriving without a schema bump would
            // mean this shell is reading a stream it does not understand.
            if (!ScanContract.IsKnownSourceStatus(status))
            {
                throw new ScanProtocolException(
                    "The scan source '" + (name ?? "?") + "' reported status '" + (status ?? "null") +
                    "', which this shell does not know. The statuses it knows are " +
                    string.Join(", ", (string[])ScanContract.SourceStatuses) + ".");
            }

            return new SourceRecord
            {
                Name = name,
                Status = status,
                Reason = JsonBind.String(map, "Reason", path + "Reason"),
                ItemCount = JsonBind.NullableInt64(map, "ItemCount", path + "ItemCount"),
                DurationSeconds = JsonBind.NullableDouble(map, "DurationSeconds", path + "DurationSeconds")
            };
        }

        private static SectionRecord ReadSection(IDictionary<string, object> map)
        {
            string key = JsonBind.String(map, "Key", "Section.Key");
            string prefix = "Section[" + (key ?? "?") + "].";

            var rows = new List<RowRecord>();
            foreach (var row in JsonBind.ObjectList(map, "Row", prefix + "Row"))
            {
                rows.Add(ReadRow(row, prefix));
            }

            var section = new SectionRecord
            {
                Key = key,
                Title = JsonBind.String(map, "Title", prefix + "Title"),
                Headline = JsonBind.StringList(map, "Headline", prefix + "Headline"),
                Note = JsonBind.StringList(map, "Note", prefix + "Note"),
                ColumnHeader = JsonBind.StringList(map, "ColumnHeader", prefix + "ColumnHeader"),
                TotalLine = JsonBind.String(map, "TotalLine", prefix + "TotalLine"),
                IsComplete = JsonBind.Bool(map, "IsComplete", prefix + "IsComplete"),
                IncompleteReason = JsonBind.String(map, "IncompleteReason", prefix + "IncompleteReason"),
                RefusedSourceName = JsonBind.StringList(map, "RefusedSourceName", prefix + "RefusedSourceName"),
                EmptyText = JsonBind.String(map, "EmptyText", prefix + "EmptyText"),
                RowCount = JsonBind.Int64(map, "RowCount", prefix + "RowCount"),
                Row = rows
            };

            // Cell and ColumnHeader are positionally parallel, and the length
            // is not fixed: the engine splices a FindingId column into every
            // row of a section whose display names collide. If they ever came
            // apart, every cell after the join would be shown under the wrong
            // heading -- a wrong answer that looks like a right one, which is
            // the failure mode this project treats as the serious kind.
            foreach (RowRecord row in rows)
            {
                if (row.Cell.Count != section.ColumnHeader.Count)
                {
                    throw new ScanProtocolException(
                        "Row " + row.Number.ToString(CultureInfo.InvariantCulture) + " of section '" +
                        (key ?? "?") + "' has " +
                        row.Cell.Count.ToString(CultureInfo.InvariantCulture) + " cells against " +
                        section.ColumnHeader.Count.ToString(CultureInfo.InvariantCulture) +
                        " column headings. They are read positionally, so they have to agree.");
                }
            }

            return section;
        }

        private static RowRecord ReadRow(IDictionary<string, object> map, string sectionPrefix)
        {
            string displayName = JsonBind.String(map, "DisplayName", sectionPrefix + "Row.DisplayName");
            string prefix = sectionPrefix + "Row[" + (displayName ?? "?") + "].";

            var row = new RowRecord
            {
                Number = JsonBind.Int64(map, "Number", prefix + "Number"),
                SectionKey = JsonBind.String(map, "SectionKey", prefix + "SectionKey"),
                DisplayName = displayName,
                Category = JsonBind.String(map, "Category", prefix + "Category"),
                SafetyLabel = JsonBind.String(map, "SafetyLabel", prefix + "SafetyLabel"),
                Cell = JsonBind.StringList(map, "Cell", prefix + "Cell"),
                FindingId = JsonBind.String(map, "FindingId", prefix + "FindingId"),
                Confidence = JsonBind.String(map, "Confidence", prefix + "Confidence"),
                RequiresConsent = JsonBind.NullableBool(map, "RequiresConsent", prefix + "RequiresConsent"),
                RemovalMethod = JsonBind.String(map, "RemovalMethod", prefix + "RemovalMethod"),
                Evidence = JsonBind.StringList(map, "Evidence", prefix + "Evidence")
            };

            // THE CATEGORY FIELDS ARE BOUND BY KEY PRESENCE, NOT BY CATEGORY.
            // The engine has a table saying which category attaches which
            // fields; restating it here would be a second copy of it, and two
            // copies of a table is somewhere for them to disagree. Presence is
            // the signal the contract actually carries, so presence is what is
            // read.
            row.HasWhitelistEntryId = JsonBind.Has(map, "WhitelistEntryId");
            if (row.HasWhitelistEntryId)
            {
                row.WhitelistEntryId = JsonBind.String(map, "WhitelistEntryId", prefix + "WhitelistEntryId");
            }

            row.HasMechanism = JsonBind.Has(map, "Mechanism");
            if (row.HasMechanism)
            {
                row.Mechanism = JsonBind.String(map, "Mechanism", prefix + "Mechanism");
            }

            row.HasFindingReason = JsonBind.Has(map, "FindingReason");
            if (row.HasFindingReason)
            {
                row.FindingReason = JsonBind.String(map, "FindingReason", prefix + "FindingReason");
            }

            row.HasStartupEntryId = JsonBind.Has(map, "StartupEntryId");
            if (row.HasStartupEntryId)
            {
                row.StartupEntryId = JsonBind.String(map, "StartupEntryId", prefix + "StartupEntryId");
            }

            row.HasLocationId = JsonBind.Has(map, "LocationId");
            if (row.HasLocationId)
            {
                row.LocationId = JsonBind.String(map, "LocationId", prefix + "LocationId");
            }

            row.HasLocationPath = JsonBind.Has(map, "LocationPath");
            if (row.HasLocationPath)
            {
                row.LocationPath = JsonBind.StringList(map, "LocationPath", prefix + "LocationPath");
            }

            row.HasEligibleBytes = JsonBind.Has(map, "EligibleBytes");
            if (row.HasEligibleBytes)
            {
                row.EligibleBytes = JsonBind.NullableInt64(map, "EligibleBytes", prefix + "EligibleBytes");
            }

            row.HasEligibleFileCount = JsonBind.Has(map, "EligibleFileCount");
            if (row.HasEligibleFileCount)
            {
                row.EligibleFileCount = JsonBind.NullableInt64(map, "EligibleFileCount", prefix + "EligibleFileCount");
            }

            row.HasIsSizeFloor = JsonBind.Has(map, "IsSizeFloor");
            if (row.HasIsSizeFloor)
            {
                row.IsSizeFloor = JsonBind.NullableBool(map, "IsSizeFloor", prefix + "IsSizeFloor");
            }

            row.HasMinimumAgeDays = JsonBind.Has(map, "MinimumAgeDays");
            if (row.HasMinimumAgeDays)
            {
                row.MinimumAgeDays = JsonBind.NullableInt64(map, "MinimumAgeDays", prefix + "MinimumAgeDays");
            }

            row.HasProfileBreakdown = JsonBind.Has(map, "ProfileBreakdown");
            if (row.HasProfileBreakdown)
            {
                var profiles = new List<ProfileBreakdownRecord>();
                foreach (var profile in JsonBind.ObjectList(map, "ProfileBreakdown", prefix + "ProfileBreakdown"))
                {
                    profiles.Add(new ProfileBreakdownRecord
                    {
                        Profile = JsonBind.String(profile, "Profile", prefix + "ProfileBreakdown.Profile"),
                        FileCount = JsonBind.NullableInt64(profile, "FileCount", prefix + "ProfileBreakdown.FileCount"),
                        TotalBytes = JsonBind.NullableInt64(profile, "TotalBytes", prefix + "ProfileBreakdown.TotalBytes"),
                        EligibleFileCount = JsonBind.NullableInt64(profile, "EligibleFileCount", prefix + "ProfileBreakdown.EligibleFileCount"),
                        EligibleBytes = JsonBind.NullableInt64(profile, "EligibleBytes", prefix + "ProfileBreakdown.EligibleBytes")
                    });
                }

                row.ProfileBreakdown = profiles;
            }

            row.HasPlan = JsonBind.Has(map, "Plan");
            if (row.HasPlan)
            {
                IDictionary<string, object> plan = JsonBind.Object(map, "Plan", prefix + "Plan");
                if (plan != null)
                {
                    row.Plan = ReadPlan(plan, prefix + "Plan.");
                }
            }

            return row;
        }

        private static PlanRecord ReadPlan(IDictionary<string, object> map, string prefix)
        {
            return new PlanRecord
            {
                Route = JsonBind.String(map, "Route", prefix + "Route"),
                Supported = JsonBind.Bool(map, "Supported", prefix + "Supported"),
                UnsupportedReason = JsonBind.String(map, "UnsupportedReason", prefix + "UnsupportedReason"),
                CurrentState = JsonBind.String(map, "CurrentState", prefix + "CurrentState"),
                VerifiedUtc = JsonBind.String(map, "VerifiedUtc", prefix + "VerifiedUtc"),
                RequiresElevation = JsonBind.Bool(map, "RequiresElevation", prefix + "RequiresElevation"),
                RequiresConsent = JsonBind.NullableBool(map, "RequiresConsent", prefix + "RequiresConsent"),
                SafetyLabel = JsonBind.String(map, "SafetyLabel", prefix + "SafetyLabel"),
                IsReversible = JsonBind.Bool(map, "IsReversible", prefix + "IsReversible"),
                Note = JsonBind.StringList(map, "Note", prefix + "Note"),
                PreviewText = JsonBind.StringList(map, "PreviewText", prefix + "PreviewText")
            };
        }
    }
}
