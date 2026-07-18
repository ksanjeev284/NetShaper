using System.Windows;

namespace NetShaper.Gui;

public partial class InputDialog : Window
{
    public string Value { get; private set; } = "";

    public InputDialog(string title, string prompt, string initial = "")
    {
        InitializeComponent();
        Title = title;
        PromptText.Text = prompt;
        ValueBox.Text = initial;
        ValueBox.SelectAll();
        Loaded += (_, _) => ValueBox.Focus();
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        Value = (ValueBox.Text ?? "").Trim();
        if (Value.Length == 0)
        {
            MessageBox.Show("Enter a value.", "NetShaper");
            return;
        }
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
