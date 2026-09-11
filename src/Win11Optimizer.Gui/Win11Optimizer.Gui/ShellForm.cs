using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Win11Optimizer.Gui.Core.Contract;
using Win11Optimizer.Gui.Core.Process;
using Win11Optimizer.Gui.Core.View;

namespace Win11Optimizer.Gui
{
    /// <summary>
    /// The window. One control filling the frame, a page inside it, and a
    /// second process feeding it.
    /// </summary>
    /// <remarks>
    /// NOTHING IS DECIDED HERE. Every screen this form shows was worked out in
    /// Win11Optimizer.Gui.Core, which is the half that has tests; this file
    /// moves finished view models across the bridge and turns clicks back into
    /// calls on them. If a screen ever needs a judgement, it belongs on the
    /// other side of that line, not in this file.
    /// </remarks>
    internal sealed class ShellForm : Form
    {
        private readonly CommandLine _commandLine;
        private readonly WebView2 _view;
        private readonly SelectionState _selection = new SelectionState();
        private readonly ScanningView _scanning = new ScanningView();
        private readonly CancellationTokenSource _cancel = new CancellationTokenSource();

        private DecisionsView _decisions;
        private CategoryTableSet _tables;
        private bool _pageReady;

        public ShellForm(CommandLine commandLine)
        {
            _commandLine = commandLine;

            Text = "win11-optimizer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(1180, 820);
            MinimumSize = new Size(760, 560);
            BackColor = Color.FromArgb(0x0d, 0x12, 0x18);

            _view = new WebView2 { Dock = DockStyle.Fill };
            Controls.Add(_view);

            Load += OnLoad;
            FormClosing += delegate { _cancel.Cancel(); };
        }

        private async void OnLoad(object sender, EventArgs e)
        {
            // The user data folder is never under Program Files: an installed
            // build runs from a folder the user cannot write to, and WebView2
            // would fail to start rather than fall back.
            string dataFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "win11-optimizer", "WebView2");

            CoreWebView2Environment environment;
            try
            {
                Directory.CreateDirectory(dataFolder);
                environment = await CoreWebView2Environment.CreateAsync(null, dataFolder);
                await _view.EnsureCoreWebView2Async(environment);
            }
            catch (Exception ex)
            {
                ShowStartupFailure(ex);
                return;
            }

            CoreWebView2 core = _view.CoreWebView2;

            // Locked down to what the bridge needs and nothing else. The page
            // is a renderer for local data; it has no reason to browse, open a
            // context menu, or reach a host object.
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreHostObjectsAllowed = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.IsZoomControlEnabled = false;
            core.Settings.IsWebMessageEnabled = true;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;

            core.WebMessageReceived += OnWebMessage;

            // The page is the only document this control will ever show.
            // Anything else -- a link, a redirect, a stray navigation -- is
            // refused rather than followed.
            core.NavigationStarting += delegate (object s, CoreWebView2NavigationStartingEventArgs args)
            {
                if (!args.Uri.StartsWith("data:", StringComparison.OrdinalIgnoreCase) &&
                    !args.Uri.Equals("about:blank", StringComparison.OrdinalIgnoreCase))
                {
                    args.Cancel = true;
                }
            };

            core.NewWindowRequested += delegate (object s, CoreWebView2NewWindowRequestedEventArgs args)
            {
                args.Handled = true;
            };

            core.NavigationCompleted += delegate
            {
                if (_pageReady)
                {
                    return;
                }

                _pageReady = true;
                Post(ScanningPayload());
                StartScan();
            };

            core.NavigateToString(WebPage.Html());
        }

        private void ShowStartupFailure(Exception ex)
        {
            Controls.Clear();
            Controls.Add(new Label
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(28),
                ForeColor = Color.FromArgb(0xe4, 0xea, 0xf1),
                Font = new Font("Segoe UI", 10.5f),
                Text = "This window could not be drawn (" + ex.GetType().Name + ": " + ex.Message +
                       "). Nothing on this PC has been read or changed."
            });
        }

        // ---- the scan ----------------------------------------------------------

        private void StartScan()
        {
            string moduleFolder = _commandLine.EnginePath;
            if (string.IsNullOrEmpty(moduleFolder))
            {
                moduleFolder = EngineLocation.FindModuleFolder(
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));
            }

            if (!EngineLocation.IsModuleFolder(moduleFolder))
            {
                Post(FailurePayload(ScanStream.LaunchFailed(
                    "The win11-optimizer engine was not found next to this program, so no scan " +
                    "was started and nothing on this PC has been read. It is normally in a " +
                    "folder called " + EngineLocation.ModuleFolderName + " beside it.")));
                return;
            }

            var request = new ScanRequest
            {
                ScriptPath = EngineLocation.ScanScriptPath(moduleFolder),
                SkipPlan = _commandLine.SkipPlan
            };

            var thread = new Thread(delegate ()
            {
                ScanOutcome outcome;
                try
                {
                    outcome = new ScanProcessRunner().Run(request, OnProgress, _cancel.Token);
                }
                catch (Exception ex)
                {
                    outcome = ScanStream.LaunchFailed(
                        "The scan could not be run (" + ex.GetType().Name + ": " + ex.Message +
                        "). Nothing on this PC has been changed.");
                }

                OnScanFinished(outcome);
            });

            thread.IsBackground = true;
            thread.Name = "win11-optimizer scan";
            thread.Start();
        }

        private void OnProgress(ProgressRecord progress)
        {
            OnUiThread(delegate
            {
                _scanning.Apply(progress);
                Post(ScanningPayload());
            });
        }

        private void OnScanFinished(ScanOutcome outcome)
        {
            OnUiThread(delegate
            {
                if (!outcome.IsFinished)
                {
                    Post(FailurePayload(outcome));
                    return;
                }

                _decisions = DecisionsView.Build(outcome.Result);
                _tables = CategoryTableSet.Build(outcome.Result);
                _selection.Retain(_decisions.Card);
                Post(DecisionsPayload());
            });
        }

        // ---- the bridge --------------------------------------------------------

        private void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            if (_decisions == null)
            {
                return;
            }

            Dictionary<string, object> message;
            try
            {
                message = Serializer().Deserialize<Dictionary<string, object>>(e.WebMessageAsJson);
            }
            catch (Exception)
            {
                return;
            }

            if (message == null || !message.ContainsKey("action"))
            {
                return;
            }

            string action = Convert.ToString(message["action"]);
            string key = message.ContainsKey("key") ? Convert.ToString(message["key"]) : null;

            // A TABLE CONTROL IS ANSWERED BY THE TABLE, NOT BY THE SELECTION.
            // The page says what was typed, clicked or sorted on; which rows
            // that leaves, and in what order, is worked out in Gui.Core and
            // comes back as a list of indices for the page to paint.
            if ((action == "table" || action == "sort") && key != null)
            {
                PostTable(action, key, message);
                return;
            }

            // The page sends what a person did. What that means is worked out
            // by SelectionState, which is on the tested side of the line.
            if (action == "toggle" && key != null)
            {
                DecisionCard card = FindCard(key);
                if (card != null)
                {
                    _selection.Toggle(card);
                }
            }
            else if (action == "selectSection" && key != null)
            {
                _selection.SelectSection(_decisions.Card, key);
            }
            else if (action == "clear")
            {
                _selection.Clear();
            }

            Post(SelectionPayload());
        }

        /// <summary>
        /// Applies one table's three controls and answers with what is now
        /// visible. A message naming a table that is not there is dropped: the
        /// page can only name one it was given, so a name that does not match
        /// is a message this build did not send.
        /// </summary>
        private void PostTable(string action, string key, IDictionary<string, object> message)
        {
            if (_tables == null)
            {
                return;
            }

            CategoryTable table = _tables.Find(key);
            if (table == null)
            {
                return;
            }

            if (action == "sort")
            {
                // A heading was clicked. What that does to the order is the
                // table's rule, not the page's.
                table.ToggleSort(ReadInt(message, "column", CategoryTable.SortColumnNone));
            }
            else
            {
                table.Apply(
                    message.ContainsKey("query") ? Convert.ToString(message["query"]) : null,
                    ReadInt(message, "classIndex", CategoryTable.ClassIndexAll),
                    table.SortColumn,
                    table.Descending);
            }

            Post(TablePayload(table));
        }

        private static int ReadInt(IDictionary<string, object> message, string name, int fallback)
        {
            if (!message.ContainsKey(name) || message[name] == null)
            {
                return fallback;
            }

            try
            {
                return Convert.ToInt32(message[name], CultureInfo.InvariantCulture);
            }
            catch (Exception)
            {
                // A value that is not a number is not repaired into one. The
                // control falls back to its off position rather than to some
                // filter nobody asked for.
                return fallback;
            }
        }

        private static bool ReadBool(IDictionary<string, object> message, string name)
        {
            return message.ContainsKey(name) && message[name] is bool && (bool)message[name];
        }

        private DecisionCard FindCard(string key)
        {
            foreach (DecisionCard card in _decisions.Card)
            {
                if (string.Equals(card.Key, key, StringComparison.Ordinal))
                {
                    return card;
                }
            }

            return null;
        }

        private object ScanningPayload()
        {
            return new
            {
                screen = "scanning",
                phase = _scanning.Phase,
                message = _scanning.Message,
                item = _scanning.Item,
                itemIndex = _scanning.ItemIndex,
                itemCount = _scanning.ItemCount,
                phaseIndex = _scanning.PhaseIndex,
                phaseCount = _scanning.PhaseCount,
                fraction = _scanning.Fraction,
                findingCountSoFar = _scanning.FindingCountSoFar,
                inventoryCountSoFar = _scanning.InventoryCountSoFar
            };
        }

        private object DecisionsPayload()
        {
            return new
            {
                screen = "decisions",
                machineName = _decisions.MachineName,
                userName = _decisions.UserName,
                generatedUtc = _decisions.GeneratedUtc,
                isElevated = _decisions.IsElevated,
                isComplete = _decisions.IsComplete,
                partialSection = _decisions.PartialSection,
                plansWereSkipped = _decisions.PlansWereSkipped,
                card = _decisions.Card,
                strip = _decisions.Strip,
                rail = _decisions.Rail,
                table = _tables != null ? _tables.Table : null,
                incomplete = _decisions.Incomplete,
                refused = _decisions.Refused,
                selected = SelectedKeys()
            };
        }

        /// <summary>
        /// One table's answer to one control change. It carries the indices and
        /// the control state and NOT the rows: the page already holds those, and
        /// posting several hundred of them back on every keystroke would be
        /// sending the table again to say which part of it to show.
        /// </summary>
        private static object TablePayload(CategoryTable table)
        {
            return new
            {
                screen = "table",
                key = table.SectionKey,
                query = table.Query,
                classIndex = table.ClassIndex,
                sortColumn = table.SortColumn,
                descending = table.Descending,
                visible = table.Visible
            };
        }

        private object SelectionPayload()
        {
            return new { screen = "selection", selected = SelectedKeys(), count = _selection.Count };
        }

        private object FailurePayload(ScanOutcome outcome)
        {
            return new
            {
                screen = "failure",
                kind = outcome.Kind.ToString(),
                message = outcome.Message,
                exitCode = outcome.ExitCode,
                standardError = outcome.StandardError,
                errorPhase = outcome.Error != null ? outcome.Error.Phase : null,
                errorType = outcome.Error != null ? outcome.Error.ExceptionType : null,
                errorMessage = outcome.Error != null ? outcome.Error.Message : null
            };
        }

        private string[] SelectedKeys()
        {
            var keys = new List<string>();
            if (_decisions != null)
            {
                foreach (DecisionCard card in _selection.Selected(_decisions.Card))
                {
                    keys.Add(card.Key);
                }
            }

            return keys.ToArray();
        }

        private void Post(object payload)
        {
            if (!_pageReady || _view.CoreWebView2 == null)
            {
                return;
            }

            _view.CoreWebView2.PostWebMessageAsJson(Serializer().Serialize(payload));
        }

        private static JavaScriptSerializer Serializer()
        {
            var serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            serializer.RecursionLimit = 128;
            return serializer;
        }

        private void OnUiThread(MethodInvoker action)
        {
            if (IsDisposed || !IsHandleCreated)
            {
                return;
            }

            if (InvokeRequired)
            {
                try
                {
                    BeginInvoke(action);
                }
                catch (InvalidOperationException)
                {
                    // The window went away while the scan was still running.
                }

                return;
            }

            action();
        }
    }

    /// <summary>
    /// The page, assembled from the three embedded resources.
    /// </summary>
    /// <remarks>
    /// It is loaded with NavigateToString, so there is no base URL and nothing
    /// can be pulled in from disk or from the network -- the stylesheet and the
    /// script are inlined here instead. That is also why the page uses no web
    /// fonts: this window has to draw the same on a machine with no network.
    /// </remarks>
    internal static class WebPage
    {
        public static string Html()
        {
            string html = Read("Win11Optimizer.Gui.Web.index.html");
            html = html.Replace("/*APP_CSS*/", Read("Win11Optimizer.Gui.Web.app.css"));
            html = html.Replace("/*APP_JS*/", Read("Win11Optimizer.Gui.Web.app.js"));
            return html;
        }

        private static string Read(string name)
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
            {
                if (stream == null)
                {
                    throw new InvalidOperationException("Embedded resource '" + name + "' is missing.");
                }

                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    return reader.ReadToEnd();
                }
            }
        }
    }
}
