using Colorful;
using System.Drawing;
using Console = Colorful.Console;

namespace UnmanagedString
{
    public static class Logger
    {
        private const string MessageStyle = "[{0}] [{1}] {2}"; // The format for log messages

        private static void Log(ReadOnlySpan<char> message, string level, Color levelColor)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message)); // Ensure the message is not null
            }

            var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); // Get current timestamp
            // Explicitly define the type of the array (because C# loves strong typing!)
            var replacements = new Formatter[]
            {
                new Formatter(timestamp, Color.Gray), // Timestamp in gray
                new Formatter($" {level}", levelColor), // Log level in specified color
                new Formatter(message.ToString(), Color.White) // Actual message in white
            };

            // Log the message with formatting (like magic, but with colors!)
            Console.WriteLineFormatted(MessageStyle, Color.Gray, replacements);
        }

        public static void Information(ReadOnlySpan<char> message) => Log(message, "INFO", Color.LightGreen); // Informational message
        public static void Success(ReadOnlySpan<char> message) => Log(message, "SUCCESS", Color.Green); // Success message (yay!)
        public static void Warning(ReadOnlySpan<char> message) => Log(message, "WARNING", Color.Yellow); // Warning message (uh-oh!)
        public static void Error(ReadOnlySpan<char> message) => Log(message, "ERROR", Color.Red); // Error message (time to panic!)
        public static void Skipped(ReadOnlySpan<char> message) => Log(message, "SKIPPED", Color.DarkGray); // Skipped message (because we can!)

        public static void Exception(Exception ex)
        {
            if (ex == null)
            {
                throw new ArgumentNullException(nameof(ex)); // Ensure the exception is not null
            }

            Log(ex.Message.AsSpan(), "EXCEPTION", Color.Red); // Log the exception message
        }
    }
}