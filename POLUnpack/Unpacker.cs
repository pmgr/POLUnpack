using PeNet;

namespace POLUnpack;

class Unpacker
{
    public static void Main(string[] args)
    {
        if (args.Length is 0 or > 2)
        {
            Console.WriteLine("Usage: POLUnpack <POL compressed binary path> [Unpacked binary path]");
            return;
        }
        
        var polPath = args[0];
        var unpackedPath = args.Length == 1 ? AddSuffix(args[0], "_unpacked") : args[1];
        
        var peFile = new PeFile(polPath);
        var bin = new POLBin(peFile);
        
        bin.UnpackTo(unpackedPath);
    }

    private static string AddSuffix(string path, string suffix)
    {
        var directory = Path.GetDirectoryName(path);
        var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(path);
        var extension = Path.GetExtension(path);

        var newFileName = fileNameWithoutExtension + suffix + extension;
        return Path.Combine(directory ?? "", newFileName);
    }
}