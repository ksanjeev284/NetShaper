using System.Windows;

namespace NetShaper.Gui;

public partial class TextViewerDialog : Window
{
    public TextViewerDialog(string title, string text)
    {
        InitializeComponent();
        Title = title;
        Body.Text = text;
    }

    private void Copy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(Body.Text ?? "");
        }
        catch
        {
            MessageBox.Show("Could not access clipboard.", "NetShaper");
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
