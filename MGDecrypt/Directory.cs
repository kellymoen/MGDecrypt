using System;
using System.Collections.Generic;
using System.Linq;

namespace MGDecrypt
{
    class Directory
    {
        public uint Hash { get; private set; }
        public uint KeyX { get; private set; }
        public uint KeyY { get; private set; }
        public uint Offset { get; private set; }
        public string FolderName { get; private set; }
        public byte[] DirectoryTable { private get; set; }

        public Directory(uint folderHash, uint folderKeyX, uint folderKeyY, string folderName, uint offset)
        {
            Hash = folderHash;
            KeyX = folderKeyX;
            KeyY = folderKeyY;
            FolderName = folderName;
            Offset = offset;
        }

        public IEnumerable<DirectoryFile> GetFilesFromTable(uint directoryLength, int directoryEntryLength)
        {
            if (DirectoryTable == null)
            {
                return Enumerable.Empty<DirectoryFile>();
            }
            List<DirectoryFile> files = new List<DirectoryFile>();
            int tableEntries = BitConverter.ToInt32(DirectoryTable, 0);
            uint tableSectorLength = ((uint)Math.Ceiling(DirectoryTable.Length / (double)2048)) * 2048;
            for (int i = 0; i < tableEntries; i++)
            {
                uint fileCheck = BitConverter.ToUInt32(DirectoryTable, i * directoryEntryLength + 4);
                if (fileCheck >> 24 == 0x7E)
                {
                    uint fOffset = BitConverter.ToUInt32(DirectoryTable, i * directoryEntryLength + directoryEntryLength) + Offset + tableSectorLength;
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
                uncryptedDataPos = lastFileOffset + lastFileSectorLength - Offset;
            }
            else
            {
                uncryptedDataPos = tableSectorLength;
            }
            if (uncryptedDataPos < directoryLength)
            {
                uint fOffset = uncryptedDataPos + Offset;
                uint fileLength = directoryLength - uncryptedDataPos;
                files.Add(new DirectoryFile(false, fOffset, fileLength));
            }
            return files;
        }
    }
}
