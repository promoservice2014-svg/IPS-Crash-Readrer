using System.Windows;

namespace IpsReader;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            MessageBox.Show($"Unexpected error:\n{args.Exception.Message}", "IPS Reader",
                MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };

        var window = new MainWindow(e.Args.Length > 0 ? e.Args[0] : null);
        window.Show();
    }
}
