using PeNet;
using PeNet.Header.Pe;

namespace POLUnpack;

public class POLBin(PeFile peFile)
{
    private PeFile PeFile { get; } = peFile;


    private static long ScanOriginalEntryPoint(Span<byte> sectionSpan, long startOffset)
    {
        var match = new byte[] { 0x83, 0xC4, 0x08, 0x61, 0xE9 };
        for (var i = (int)startOffset; i < sectionSpan.Length; i++)
        {
            if (!sectionSpan[i..(i + 5)].SequenceEqual(match))
                continue;
            
            var relAddr = BitConverter.ToInt32(sectionSpan[(i + 5)..(i + 9)]);

            return i + 9 + relAddr;
        }

        throw new ArgumentException("Couldn't find the original entry point. Unknown instance of POL packer?");
    }
    
    
    private long RVAToFileOffset(uint rva)
    {
        if (PeFile.ImageSectionHeaders is null)
            throw new ArgumentException("PeFile has no image section headers");
        
        foreach (var section in PeFile.ImageSectionHeaders)
        {
            if (rva >= section.VirtualAddress && rva <= section.VirtualAddress + section.SizeOfRawData)
            {
                return section.PointerToRawData + (rva - section.VirtualAddress);
            }
        }

        throw new ArgumentException("Couldn't find the section the RVA belongs to, file's fucked probably");
    }

    private ImageSectionHeader? GetSectionByName(string sectionName) =>
        (PeFile.ImageSectionHeaders ?? throw new InvalidOperationException("ImageSectionHeaders must not be null."))
        .FirstOrDefault(s => s.Name == sectionName);
    
    
    private static byte[] DecompressPOL(Span<byte> data)
    {
        var bitStream = new BitStream(data);
        var decompressedData = new List<byte>();
        var controlBits = bitStream.GetSubBitStream(8);

        while (bitStream.HasBits())
        {
            var bit = controlBits.GetBit(true);
            if (!bit.HasValue)
            {
                controlBits = bitStream.GetSubBitStream(8);
                bit = controlBits.GetBit(true);
            }

            if (!bit.HasValue)
            {
                throw new ArgumentException("Things went to shit while decompressing the .POL1 section. Fucked file?");
            }
            
            if (bit.Value)
            {
                var b = bitStream.GetBits(8);
                decompressedData.Add((byte)b);
            }
            else
            {
                var bits = (bitStream.GetBits(8) << 8) | bitStream.GetBits(8);
                var offset = bits & 0xFFF;
                if (offset == 0)
                    break;

                var length = ((bits >> 12) & 0xF) + 3;
                var start = decompressedData.Count - offset;
                for (var i = 0; i < length; i++)
                    decompressedData.Add(decompressedData[(int)start + i]);
            }
        }
        
        return decompressedData.ToArray();
    }
    
    private void ResizeSection(string name, byte[] unalignedNewData)
    {
        if (PeFile.ImageNtHeaders is null)
            throw new ArgumentException("IMAGE_NT_HEADERS must not be null");
        
        if (PeFile.ImageDosHeader is null)
            throw new ArgumentException("IMAGE_DOS_HEADER must not be null");
        
        if (PeFile.ImageSectionHeaders is null)
            throw new ArgumentException("ImageSectionHeaders must not be null");

        var sectionToResize = GetSectionByName(name);
        if (sectionToResize is null)
            throw new ArgumentException("Section {0} was not found", name);

        sectionToResize.SizeOfRawData =
            (uint)(
                Math.Ceiling(unalignedNewData.Length / (double)PeFile.ImageNtHeaders!.OptionalHeader.FileAlignment)
                * PeFile.ImageNtHeaders!.OptionalHeader.FileAlignment
                );
        
        var newSections = PeFile.ImageSectionHeaders.Where(s => s.Name != name).ToArray();

        var blockStart = uint.MaxValue;
        var blockEnd = uint.MinValue;
        var newBlockStart = sectionToResize.PointerToRawData + sectionToResize.SizeOfRawData;
        foreach (var s in newSections)
        {
            if (s.PointerToRawData < sectionToResize.PointerToRawData)
                continue;
            
            blockStart = Math.Min(blockStart, s.PointerToRawData);
            blockEnd = Math.Max(blockEnd, s.PointerToRawData + s.SizeOfRawData);

            s.PointerToRawData += sectionToResize.SizeOfRawData;
        }
        
        
        var blockSpan = PeFile.RawFile.AsSpan(blockStart, PeFile.RawFile.Length - blockStart);
        var blockBytes = blockSpan.ToArray();
        
        PeFile.RawFile.AppendBytes(new byte[sectionToResize.SizeOfRawData]);
        PeFile.RawFile.WriteBytes(newBlockStart, blockBytes);
        PeFile.RawFile.WriteBytes(blockStart, new byte[newBlockStart - blockStart]);
        PeFile.RawFile.WriteBytes(blockStart, unalignedNewData);
    }
    
    public void UnpackTo(string path)
    {
        var ntHeaders = PeFile.ImageNtHeaders;

        if (ntHeaders is null)
            throw new ArgumentException("IMAGE_NT_HEADERS must not be null");
        
        var unpackerEntryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
        var fileOffsetUnpackerEntryPoint = RVAToFileOffset(unpackerEntryPoint);

        var polSection = GetSectionByName("POL1");
        if (polSection is null)
            throw new ArgumentException("PE file has no POL1 section, might be unpacked already or never was packed");
        
        var textSection = GetSectionByName(".text");
        if (textSection is null)
            throw new ArgumentException("PE file has no .text section, file might not be packed with the POL packer");
        
        var polSectionSpan = PeFile.RawFile.AsSpan(polSection.PointerToRawData, polSection.SizeOfRawData);
        var polSectionOffsetUnpackerEntryPoint = fileOffsetUnpackerEntryPoint - polSection.PointerToRawData;
        var originalEntryPoint = ScanOriginalEntryPoint(polSectionSpan, polSectionOffsetUnpackerEntryPoint);
        
        ntHeaders.OptionalHeader.AddressOfEntryPoint = 
            (uint)(textSection.VirtualAddress + polSection.VirtualAddress + originalEntryPoint - ntHeaders.OptionalHeader.SizeOfHeaders);

        var decompressedTextSection = DecompressPOL(polSectionSpan);
        
        PeFile.RemoveSection("POL1");
        ResizeSection(".text", decompressedTextSection);
        textSection.Characteristics = ScnCharacteristicsType.CntCode |
                                      ScnCharacteristicsType.MemExecute |
                                      ScnCharacteristicsType.MemRead;

        var newPeFile = new PeFile(PeFile.RawFile);
        
        // This is only really prepped for the samples I saw, and it's just aesthetics. If it blows up here, let me know
        if (newPeFile.ImageDebugDirectory?.Length > 0)
        {
            newPeFile.ImageDebugDirectory[0].PointerToRawData =
                (uint)(newPeFile.RawFile.Length - newPeFile.ImageDebugDirectory[0].SizeOfData);
        }

        using var f = File.OpenWrite(path);
        f.Write(newPeFile.RawFile.AsSpan(0, newPeFile.FileSize));
    }
}