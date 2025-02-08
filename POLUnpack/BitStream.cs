namespace POLUnpack;

// Implementation is a bit naff, but it was done off the cuff and works well enough
public class BitStream(Span<byte> data)
{
    private readonly byte[] _buffer = data.ToArray();
    private int _byteIndex;
    private int _bitIndex;


    public BitStream GetSubBitStream(int count)
    {
        var bytes = new List<byte>();
        var bitsRemaining = count;

        while (bitsRemaining > 0)
        {
            var bitsToRead = Math.Min(8, bitsRemaining);
            var extractedBits = (byte)GetBits(bitsToRead);
            bytes.Add(extractedBits);
            bitsRemaining -= bitsToRead;
        }

        return new BitStream(bytes.ToArray());
    }
    
    public bool HasBits()
    {
        return _byteIndex < _buffer.Length;
    }

    public bool? GetBit(bool reverse = false)
    {
        if (_byteIndex >= _buffer.Length)
        {
            return null;
        }

        var bit = reverse ? 
            ((_buffer[_byteIndex] << _bitIndex) & 0x80) >> 7 :
            _buffer[_byteIndex] >> _bitIndex & 1;

        if (++_bitIndex != 8)
            return bit == 1;
        
        _bitIndex = 0;
        _byteIndex++;

        return bit == 1;
    }

    public uint GetBits(int count)
    {
        uint result = 0;
        for (var i = 0; i < count; i++)
        {
            var bit = GetBit();
            if (!bit.HasValue)
            {
                break;
            }
            var ubit = bit.Value ? 1 : 0;
            result |= (uint)(ubit << i);
        }

        return result;
    }
}