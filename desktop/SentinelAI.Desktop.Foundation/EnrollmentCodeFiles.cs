using System.Text;
using SentinelAI.Enrollment;

namespace SentinelAI.Desktop.Foundation;

// Saves each issued code as its own ".sentinelai-enroll" file; never overwrites an existing file.
public static class EnrollmentCodeFiles
{
    public static IReadOnlyList<string> Write(string directory, IReadOnlyList<IssuedCodeRow> codes)
    {
        if (!Path.IsPathFullyQualified(directory) || !Directory.Exists(directory)) throw new DirectoryNotFoundException();
        var paths = new List<string>(codes.Count);
        for (var index = 0; index < codes.Count; index++)
        {
            if (!EnrollmentCode.TryParse(codes[index].Code, out _)) throw new InvalidDataException("An enrollment code is malformed.");
            var path = Path.Combine(directory, $"SentinelAI-computer-{index + 1:00}-{codes[index].Id.ToString("N")[..8]}{EnrollmentCode.FileExtension}");
            using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            file.Write(Encoding.ASCII.GetBytes(codes[index].Code + "\r\n"));
            paths.Add(path);
        }
        return paths;
    }
}
