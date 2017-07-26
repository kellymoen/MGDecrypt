using System;
using System.Collections.Generic;

namespace MGDecrypt
{
    class Directory
    {
        public uint hash;
        public uint keyX;
        public uint keyY;
        public uint offset;
        public string folderName;
        byte[] directoryTable;

        public Directory(uint folderHash, uint folderKeyX, uint folderKeyY, string folderName, uint offset)
        {
            this.hash = folderHash;
            this.keyX = folderKeyX;
            this.keyY = folderKeyY;
            this.folderName = folderName;
            this.offset = offset;
        }

        public void SetDirectoryTable(byte[] directoryTable)
        {
            this.directoryTable = directoryTable;
        }

        public List<DirectoryFile> GetFilesFromTable(uint directoryLength, int directoryEntryLength)
        {
            if (directoryTable == null)
            {
                return null;
            }
            List<DirectoryFile> files = new List<DirectoryFile>();
            int tableEntries = BitConverter.ToInt32(directoryTable, 0);
            uint tableSectorLength = ((uint)Math.Ceiling(directoryTable.Length / (double)2048)) * 2048;
            for (int i = 0; i < tableEntries; i++)
            {
                uint fileCheck = BitConverter.ToUInt32(directoryTable, i * directoryEntryLength + 4);
                if (fileCheck >> 24 == 0x7E)
                {
                    uint fOffset = BitConverter.ToUInt32(directoryTable, i * directoryEntryLength + directoryEntryLength) + offset + tableSectorLength;
                    uint fileLength = fileCheck ^ 0x7E000000;
                    files.Add(new DirectoryFile(true, fOffset, fileLength));
                }
            }
            //Get unencrypted data offsets/lengths -- from the sector after the length of the crypted file to the length of the directory,
            //if there is any
            //First if there's crypted data -- I think there always is
            uint uncryptedDataPos;
            if (files.Count > 0)
            {
                uint lastFileSectorLength = ((uint)Math.Ceiling(files[files.Count - 1].Length / (double)2048)) * 2048;
                uint lastFileOffset = (files[files.Count - 1].Offset);
                uncryptedDataPos = lastFileOffset + lastFileSectorLength - offset;
            }
            else
            {
                uncryptedDataPos = tableSectorLength;
            }
            if (uncryptedDataPos < directoryLength)
            {
                uint fOffset = uncryptedDataPos + offset;
                uint fileLength = directoryLength - uncryptedDataPos;
                files.Add(new DirectoryFile(false, fOffset, fileLength));
            }
            return files;
        }
    }
}
