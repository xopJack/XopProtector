using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

public partial class App : Application
{
    /// <summary>
    /// Named mutex checked by Inno Setup <c>AppMutex</c> so upgrades can detect a running UI.
    /// Keep a static root so the OS handle lives for the process lifetime.
    /// </summary>
    private static Mutex? _setupDetectMutex;

    private const string SetupDetectMutexName = "XopProtector.SingleInstance.Mutex";

    protected override void OnStartup(StartupEventArgs e)
    {
        HoldSetupDetectMutex();
        AppDataPaths.EnsureReady();
        LocalizationService.Initialize();
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
                TryShowFatal(ex);
        };
        ThemeService.Initialize();
    }

    private static void HoldSetupDetectMutex()
    {
        // Prefer Global\ so an elevated Setup can see a medium-IL user session.
        // Fall back to session-local if Global\ creation is denied.
        try
        {
            _setupDetectMutex = new Mutex(false, @"Global\" + SetupDetectMutexName);
            return;
        }
        catch
        {
            // ignore and try session mutex
        }
        try
        {
            _setupDetectMutex = new Mutex(false, SetupDetectMutexName);
        }
        catch
        {
            // Installer CloseApplications / taskkill remain as fallback.
        }
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryShowFatal(e.Exception);
        e.Handled = true;
    }

    private static void TryShowFatal(Exception ex)
    {
        try
        {
            MessageBox.Show(
                string.Format(Strings.Msg_UnhandledError, ex.GetType().Name, ex.Message),
                Strings.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
            // ignore
        }
    }
}
