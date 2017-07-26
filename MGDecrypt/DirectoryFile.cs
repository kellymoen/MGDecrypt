namespace MGDecrypt
{
    class DirectoryFile
    {
        public bool Crypted { get; private set; }
        public uint Offset { get; private set; }
        public uint Length { get; private set; }

        public DirectoryFile(bool crypted, uint offset, uint length)
        {
            Crypted = crypted;
            Offset = offset;
            Length = length;
        }
    }
}
