namespace MGDecrypt
{
    class DirectoryFile
    {
        public bool crypted;
        public uint offset;
        public uint length;

        public DirectoryFile(bool crypted, uint offset, uint length)
        {
            this.crypted = crypted;
            this.offset = offset;
            this.length = length;

        }
    }
}
