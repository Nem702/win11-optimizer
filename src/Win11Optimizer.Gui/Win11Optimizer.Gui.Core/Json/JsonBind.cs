using System;
using System.Collections.Generic;
using System.Globalization;
using System.Web.Script.Serialization;

namespace Win11Optimizer.Gui.Core.Json
{
    /// <summary>
    /// Reading one protocol line into plain values, strictly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// THE TOKENIZER IS JavaScriptSerializer, which is in the box on .NET
    /// Framework. That is why it was chosen: the shipped application gains no
    /// DLL for reading the contract, in a tool whose pitch is removing things.
    /// It hands back a dictionary for an object and an object array for an
    /// array, which makes KEY PRESENCE the natural test -- and key presence is
    /// the distinction this contract is built on.
    /// </para>
    /// <para>
    /// EVERYTHING ABOVE THE TOKENIZER IS WRITTEN OUT BY HAND, field by field.
    /// No reflection, no attributes, no convention. A deserializer that mapped
    /// by name would invent a default for every field it did not find, and the
    /// one thing this contract cannot survive is a missing field arriving as a
    /// zero.
    /// </para>
    /// <para>
    /// AND IT THROWS ON ANY LEAF TYPE IT DID NOT EXPECT. Review\Json.ps1's
    /// writer throws on any type it cannot serialize, and that is what makes
    /// "no scriptblock survives" a mechanical claim rather than a search for a
    /// string. This is the same guarantee from the other end: the writer
    /// refuses to send what it cannot represent, the reader refuses to accept
    /// what it did not expect.
    /// </para>
    /// </remarks>
    internal static class JsonBind
    {
        /// <summary>
        /// One line to a dictionary. The protocol is JSON Lines, so a line is
        /// exactly one complete object.
        /// </summary>
        public static IDictionary<string, object> ParseObject(string line)
        {
            if (line == null)
            {
                throw new ScanProtocolException("A null line cannot be parsed.");
            }

            var serializer = new JavaScriptSerializer();

            // The real result line is around 57 KB on this machine and the
            // default cap is 2 MB, so this is headroom rather than a fix. It is
            // set explicitly because a cap that is hit produces an exception
            // about JSON length rather than about the scan, and the next person
            // to read that message should not have to discover the default.
            serializer.MaxJsonLength = int.MaxValue;
            serializer.RecursionLimit = 128;

            object parsed;
            try
            {
                parsed = serializer.DeserializeObject(line);
            }
            catch (Exception ex)
            {
                throw new ScanProtocolException(
                    "A line of the scan output is not valid JSON: " + ex.Message, ex);
            }

            var map = parsed as IDictionary<string, object>;
            if (map == null)
            {
                throw new ScanProtocolException(
                    "A line of the scan output parsed as " + DescribeType(parsed) +
                    " rather than as a JSON object. The protocol is one complete object per line.");
            }

            return map;
        }

        public static bool Has(IDictionary<string, object> map, string key)
        {
            return map.ContainsKey(key);
        }

        /// <summary>The raw value, checked against the types this contract can carry.</summary>
        public static object Value(IDictionary<string, object> map, string key, string path)
        {
            object value;
            if (!map.TryGetValue(key, out value))
            {
                return null;
            }

            Check(value, path);
            return value;
        }

        /// <summary>
        /// Refuses anything the contract cannot legally contain, naming the
        /// type it found and the field it found it in.
        /// </summary>
        private static void Check(object value, string path)
        {
            if (value == null || value is string || value is bool ||
                value is int || value is long || value is decimal || value is double)
            {
                return;
            }

            // A DateTime here means the payload carried a Microsoft date
            // literal and the tokenizer turned it back into a date. That
            // literal is what the 5.1 serializer emits for a [datetime] --
            // Q29, the exact shell divergence the engine writes ISO-8601 text
            // to avoid. It is never legal in this contract, and it is worth
            // saying why rather than just refusing a type.
            if (value is DateTime)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' carried a Microsoft date literal rather than " +
                    "ISO-8601 text. Every timestamp in this contract is an explicit string on " +
                    "both shells (Q29); a date literal means the payload did not come from " +
                    "Review\\Json.ps1.");
            }

            if (value is IDictionary<string, object> || value is object[])
            {
                return;
            }

            throw new ScanProtocolException(
                "The field '" + path + "' carried " + DescribeType(value) +
                ", which this contract does not use.");
        }

        public static string String(IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return null;
            }

            var text = value as string;
            if (text == null)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' should be text but carried " + DescribeType(value) + ".");
            }

            return text;
        }

        /// <summary>
        /// A list of strings, normalised out of the three shapes the same field
        /// can arrive in.
        /// </summary>
        /// <remarks>
        /// THIS IS THE TRAP THAT BREAKS A NAIVE CONSUMER. Every string
        /// collection in the payload is produced by a PowerShell function
        /// returning a string array, and PowerShell unrolls a function's array
        /// output onto the pipeline. So the same field is null when it holds
        /// nothing, a BARE STRING when it holds one thing, and an array only
        /// when it holds two or more. Section Note, row Evidence,
        /// RefusedSourceName and Plan.PreviewText all do this, and the golden
        /// fixture carries both shapes of three of them.
        /// </remarks>
        public static IReadOnlyList<string> StringList(
            IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);

            if (value == null)
            {
                return new string[0];
            }

            var single = value as string;
            if (single != null)
            {
                return new[] { single };
            }

            var items = value as object[];
            if (items == null)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' should be text or a list of text but carried " +
                    DescribeType(value) + ".");
            }

            var result = new string[items.Length];
            for (int i = 0; i < items.Length; i++)
            {
                var item = items[i] as string;
                if (item == null)
                {
                    throw new ScanProtocolException(
                        "Element " + i.ToString(CultureInfo.InvariantCulture) + " of '" + path +
                        "' should be text but carried " + DescribeType(items[i]) +
                        ". The engine drops a null from a list of lines rather than writing it.");
                }

                result[i] = item;
            }

            return result;
        }

        /// <summary>
        /// An array of objects. These fields are assigned inline by the engine
        /// rather than returned from a function, so they never collapse: Scan,
        /// Source, Section, Row and ProfileBreakdown are real arrays at any
        /// length, including zero.
        /// </summary>
        public static IReadOnlyList<IDictionary<string, object>> ObjectList(
            IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return new IDictionary<string, object>[0];
            }

            var items = value as object[];
            if (items == null)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' should be a list of objects but carried " +
                    DescribeType(value) + ".");
            }

            var result = new IDictionary<string, object>[items.Length];
            for (int i = 0; i < items.Length; i++)
            {
                var item = items[i] as IDictionary<string, object>;
                if (item == null)
                {
                    throw new ScanProtocolException(
                        "Element " + i.ToString(CultureInfo.InvariantCulture) + " of '" + path +
                        "' should be an object but carried " + DescribeType(items[i]) + ".");
                }

                result[i] = item;
            }

            return result;
        }

        public static IDictionary<string, object> Object(
            IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return null;
            }

            var nested = value as IDictionary<string, object>;
            if (nested == null)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' should be an object but carried " +
                    DescribeType(value) + ".");
            }

            return nested;
        }

        /// <summary>A boolean the contract guarantees. Absent or null is a violation.</summary>
        public static bool Bool(IDictionary<string, object> map, string key, string path)
        {
            bool? value = NullableBool(map, key, path);
            if (!value.HasValue)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' is required to be true or false, and it was not there.");
            }

            return value.Value;
        }

        /// <summary>
        /// A boolean that may legitimately be null. RequiresConsent is the
        /// motivating field: the engine refuses to coerce it, because the
        /// safety rule fails closed on anything that is not a real boolean and
        /// repairing the value on the way through would hide exactly what that
        /// clause exists to catch. So nothing is repaired here either.
        /// </summary>
        public static bool? NullableBool(IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return null;
            }

            if (value is bool)
            {
                return (bool)value;
            }

            throw new ScanProtocolException(
                "The field '" + path + "' should be true or false but carried " +
                DescribeType(value) + ".");
        }

        public static long Int64(IDictionary<string, object> map, string key, string path)
        {
            long? value = NullableInt64(map, key, path);
            if (!value.HasValue)
            {
                throw new ScanProtocolException(
                    "The field '" + path + "' is required to be a whole number, and it was not there.");
            }

            return value.Value;
        }

        public static long? NullableInt64(IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return null;
            }

            if (value is int)
            {
                return (int)value;
            }

            if (value is long)
            {
                return (long)value;
            }

            // The engine writes whole values as whole numbers, so a fraction
            // in one of these fields is a contract violation rather than
            // something to round off quietly.
            if (value is decimal)
            {
                var d = (decimal)value;
                if (decimal.Truncate(d) == d)
                {
                    return (long)d;
                }
            }

            if (value is double)
            {
                var d = (double)value;
                if (!double.IsInfinity(d) && !double.IsNaN(d) && Math.Floor(d) == d)
                {
                    return (long)d;
                }
            }

            throw new ScanProtocolException(
                "The field '" + path + "' should be a whole number but carried " +
                DescribeType(value) + ".");
        }

        public static double? NullableDouble(IDictionary<string, object> map, string key, string path)
        {
            object value = Value(map, key, path);
            if (value == null)
            {
                return null;
            }

            if (value is int)
            {
                return (int)value;
            }

            if (value is long)
            {
                return (long)value;
            }

            if (value is decimal)
            {
                return (double)(decimal)value;
            }

            if (value is double)
            {
                return (double)value;
            }

            throw new ScanProtocolException(
                "The field '" + path + "' should be a number but carried " +
                DescribeType(value) + ".");
        }

        private static string DescribeType(object value)
        {
            if (value == null)
            {
                return "null";
            }

            if (value is object[])
            {
                return "a list";
            }

            if (value is IDictionary<string, object>)
            {
                return "an object";
            }

            return "a value of type " + value.GetType().Name;
        }
    }
}
