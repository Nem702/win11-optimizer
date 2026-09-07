using System;
using System.Drawing;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;

namespace Win11Optimizer.Gui
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            CommandLine commandLine = CommandLine.Parse(args);

            string missing = WebView2Unavailable();
            if (missing != null)
            {
                Application.Run(new MissingRuntimeForm(missing));
                return;
            }

            Application.Run(new ShellForm(commandLine));
        }

        /// <summary>
        /// Returns a sentence when WebView2 cannot be used, and null when it
        /// can.
        /// </summary>
        /// <remarks>
        /// <para>
        /// WebView2 comes with Edge on Windows 11, so on the machine this tool
        /// is for it is already there. It is not guaranteed on Windows 10, and
        /// a shell that threw a first-chance exception dialog at somebody
        /// because a component was missing would be a bad answer to a
        /// reasonable situation.
        /// </para>
        /// <para>
        /// The Evergreen installer is deliberately NOT bundled. This tool's
        /// whole pitch is removing things from a machine, and shipping a
        /// hundred megabytes of browser to display four cards would refute it.
        /// The sentence says what is missing and where it comes from, and
        /// stops.
        /// </para>
        /// </remarks>
        private static string WebView2Unavailable()
        {
            try
            {
                string version = CoreWebView2Environment.GetAvailableBrowserVersionString();
                if (string.IsNullOrEmpty(version))
                {
                    return "The Microsoft Edge WebView2 Runtime reported no version, so this " +
                           "window cannot be drawn.";
                }

                return null;
            }
            catch (WebView2RuntimeNotFoundException)
            {
                return "The Microsoft Edge WebView2 Runtime is not installed on this PC, and " +
                       "win11-optimizer uses it to draw this window. It ships with Microsoft " +
                       "Edge on Windows 11 and is available from Microsoft as the \"WebView2 " +
                       "Runtime\" for Windows 10. Nothing on this PC has been read or changed.";
            }
            catch (DllNotFoundException)
            {
                // WebView2Loader.dll is missing beside the executable. Its own
                // failure, and a different sentence, because installing the
                // runtime would not fix it.
                return "A file win11-optimizer needs to draw this window (WebView2Loader.dll) is " +
                       "not beside the program. Nothing on this PC has been read or changed.";
            }
        }
    }

    /// <summary>
    /// The whole fallback: a window, a sentence, and no attempt to carry on.
    /// </summary>
    internal sealed class MissingRuntimeForm : Form
    {
        public MissingRuntimeForm(string message)
        {
            Text = "win11-optimizer";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(620, 200);
            MinimumSize = new Size(460, 200);
            BackColor = Color.FromArgb(0x14, 0x1b, 0x23);

            var label = new Label
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(28, 26, 28, 26),
                Text = message,
                ForeColor = Color.FromArgb(0xe4, 0xea, 0xf1),
                Font = new Font("Segoe UI", 10.5f),
                UseCompatibleTextRendering = false
            };

            Controls.Add(label);
        }
    }
}
