using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using IpsReader.Core;
using Microsoft.Win32;

namespace IpsReader;

public partial class MainWindow : Window
{
    const string ProgId = "IpsReader.CrashReport";
    ReportViewModel? _vm;

    public MainWindow(string? initialFile = null)
    {
        InitializeComponent();
        if (!string.IsNullOrEmpty(initialFile))
            Loaded += (_, _) => OpenFile(initialFile);
    }

    void OpenFile(string path)
    {
        try
        {
            var report = IpsParser.Load(path);
            var analysis = CrashAnalyzer.Analyze(report);
            _vm = new ReportViewModel(report, analysis);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Unable to read the file:\n{ex.Message}", "IPS Reader",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        DataContext = _vm;
        ReportBox.Text = _vm.ReportText;
        JsonBox.Text = _vm.RawJson;
        ThreadList.SelectedItem = _vm.InitialThread;
        if (ThreadList.SelectedItem is not null) ThreadList.ScrollIntoView(ThreadList.SelectedItem);

        DropZone.Visibility = Visibility.Collapsed;
        Tabs.Visibility = Visibility.Visible;
        Tabs.SelectedIndex = 0;
        CopyButton.IsEnabled = true;

        Title = $"{Path.GetFileName(path)} — IPS Reader";
        FileLabel.Text = path;
        var r = _vm.Report;
        StatusText.Text = $"{r.BugTypeName} · {r.Threads.Count} threads · {r.Images.Count} binary images" +
                          (r.IsLegacyText ? " · text format" : " · JSON format");
        CommandManager.InvalidateRequerySuggested();
    }

    // ── Thread ────────────────────────────────────────────────────────────

    void ThreadList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        var thread = ThreadList.SelectedItem as ThreadInfo;
        ThreadTitle.Text = thread?.DisplayTitle ?? "";
        ThreadSubtitle.Text = thread is null ? "" : $"{thread.DisplaySubtitle} · {thread.Frames.Count} frames";
        FramesGrid.ItemsSource = thread?.Frames;
        RegistersGrid.ItemsSource = thread?.Registers;
        RegistersExpander.Visibility = thread is { Registers.Count: > 0 } ? Visibility.Visible : Visibility.Collapsed;
        ApplyFrameFilter();
    }

    void AppOnly_Changed(object sender, RoutedEventArgs e) => ApplyFrameFilter();

    void ApplyFrameFilter()
    {
        if (FramesGrid.ItemsSource is null) return;
        var view = CollectionViewSource.GetDefaultView(FramesGrid.ItemsSource);
        view.Filter = AppOnlyCheck.IsChecked == true ? o => o is FrameInfo { IsAppCode: true } : null;
    }

    // ── Commands ───────────────────────────────────────────────────────────

    void Open_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Open crash report",
            Filter = "iOS crash reports (*.ips;*.crash)|*.ips;*.crash|JSON files (*.json)|*.json|All files (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) == true) OpenFile(dlg.FileName);
    }

    void HasReport_CanExecute(object sender, CanExecuteRoutedEventArgs e) => e.CanExecute = _vm is not null;

    void Save_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (_vm is null) return;
        var baseName = Path.GetFileNameWithoutExtension(_vm.Report.FilePath) ?? "report";
        var dlg = new SaveFileDialog
        {
            Title = "Export report",
            FileName = baseName + ".txt",
            Filter = "Text report (*.txt)|*.txt|Crash report (*.crash)|*.crash|Diagnosis + report (*.txt)|*.txt",
        };
        if (dlg.ShowDialog(this) != true) return;

        var content = dlg.FilterIndex == 3
            ? _vm.DiagnosisText() + "\n" + new string('=', 80) + "\n\n" + _vm.ReportText
            : _vm.ReportText;
        File.WriteAllText(dlg.FileName, content);
        StatusText.Text = $"Report exported to {dlg.FileName}";
    }

    void Find_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        if (Tabs.SelectedItem == JsonTab)
        {
            JsonFindBox.Focus();
            JsonFindBox.SelectAll();
            return;
        }
        Tabs.SelectedItem = ReportTab;
        Dispatcher.BeginInvoke(() => { ReportFindBox.Focus(); ReportFindBox.SelectAll(); });
    }

    void CopyDiagnosis_Click(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        Clipboard.SetText(_vm.DiagnosisText());
        StatusText.Text = "Diagnosis copied to the clipboard";
    }

    // ── Text search ─────────────────────────────────────────────────

    void FindBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter) return;
        FindNext((TextBox)sender);
        e.Handled = true;
    }

    void FindNext_Click(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).Tag is TextBox box) FindNext(box);
    }

    void FindNext(TextBox findBox)
    {
        if (findBox.Tag is not TextBox target || string.IsNullOrEmpty(findBox.Text)) return;
        var text = target.Text;
        int start = target.SelectionStart + target.SelectionLength;
        int idx = text.IndexOf(findBox.Text, Math.Min(start, text.Length), StringComparison.OrdinalIgnoreCase);
        if (idx < 0) idx = text.IndexOf(findBox.Text, StringComparison.OrdinalIgnoreCase); // wrap around to the start
        if (idx < 0)
        {
            StatusText.Text = $"\"{findBox.Text}\" not found";
            return;
        }

        target.Focus();
        target.Select(idx, findBox.Text.Length);
        target.ScrollToLine(target.GetLineIndexFromCharacterIndex(idx));
        StatusText.Text = $"Found at line {target.GetLineIndexFromCharacterIndex(idx) + 1}";
    }

    void Wrap_Changed(object sender, RoutedEventArgs e) =>
        ReportBox.TextWrapping = WrapCheck.IsChecked == true ? TextWrapping.Wrap : TextWrapping.NoWrap;

    // ── Drag & drop ───────────────────────────────────────────────────────

    void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
        {
            OpenFile(files[0]);
            e.Handled = true;
        }
    }

    // ── File association ─────────────────────────────────────────────────

    void Associate_Click(object sender, RoutedEventArgs e)
    {
        var exe = Environment.ProcessPath;
        if (exe is null) return;

        var answer = MessageBox.Show(this,
            "Do you want to open .ips and .crash files with IPS Reader by double-clicking them?\n\n" +
            $"This executable will be registered (for your user only):\n{exe}\n\n" +
            "If you move the app to another folder, repeat this step.",
            "Associate files", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (answer != MessageBoxResult.Yes) return;

        try
        {
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}"))
                k.SetValue("", "iOS crash report");
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}\DefaultIcon"))
                k.SetValue("", $"\"{exe}\",0");
            using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ProgId}\shell\open\command"))
                k.SetValue("", $"\"{exe}\" \"%1\"");

            foreach (var ext in new[] { ".ips", ".crash" })
            {
                using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ext}"))
                    k.SetValue("", ProgId);
                using (var k = Registry.CurrentUser.CreateSubKey($@"Software\Classes\{ext}\OpenWithProgids"))
                    k.SetValue(ProgId, Array.Empty<byte>(), RegistryValueKind.None);
            }

            SHChangeNotify(0x08000000 /* SHCNE_ASSOCCHANGED */, 0, IntPtr.Zero, IntPtr.Zero);
            MessageBox.Show(this,
                "Association complete.\n\nIf Windows still uses another app, right-click an .ips file → " +
                "Open with → Choose another app → IPS Reader → \"Always\".",
                "Associate files", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Unable to register the association:\n{ex.Message}", "Associate files",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [DllImport("shell32.dll")]
    static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);
}
