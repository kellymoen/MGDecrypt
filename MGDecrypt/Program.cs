using System;
using System.Collections.Generic;
using System.IO;

namespace MGDecrypt
{
    class Program
    {
        private const int KEY_CONST = 0x02E90EDD;

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.Write("Usage mgdecrypt infile outfile -game");
                Console.Write("game options -- zoe2 mgs2 mgs3");
                return;
            }

            Game game = null;
            try
            {
                game = Game.GetGameByName(args[2]);
            }
            catch (NotImplementedException)
            {
                Console.WriteLine("Unknown game: {0}", args[2]);
                Console.WriteLine("Known games: zoe2 mgs2 mgs3");
                return;
            }

            Decrypt(args[0], args[1], game);
        }

        public static uint HashFolderName(byte[] folderName)
        {
            uint bitmask = 0xffffff;
            int i = 0;
            uint hashed = 0;
            do
            {
                uint hashRight = hashed >> 0x13;
                uint hashLeft = hashed << 0x5;
                hashed = hashLeft | hashRight;
                hashed += folderName[i];
                hashed &= bitmask;
                i++;
            } while (folderName[i] != 0 && i < folderName.Length-1);
            return hashed;
        }

        public static uint HashFolderNameZOE(byte[] folderName)
        {
            uint bitmask = 0xf;
            int i = 0;
            uint hashed = 0;
            uint hashed2 = 0;
            uint a0 = 0;
            uint a1 = folderName[0];
            uint a2 = 0;
            do
            {
                hashed = (uint)i & bitmask;
                hashed = a1 << (byte)hashed;
                a0 = a2 >> 3;
                hashed2 = a1 & bitmask;
                a0 += hashed;
                a0 += a1;
                hashed2 = a2 << (byte)hashed2;
                i++;
                a1 = folderName[i];
                hashed2 |= a0;
                a2 += hashed2;
            } while (folderName[i] != 0 && i < folderName.Length - 1);
            return a2;
        }

        public static uint MakeFolderKeyX(uint folderHash, uint rootKey)
        {
            uint folderConst = 0xA78925D9;
            uint folderKey = folderHash << 0x7;
            folderKey += rootKey;
            folderKey += folderHash;
            folderKey += folderConst;
            return folderKey;
        }

        public static uint MakeFolderKeyY(uint folderHash)
        {
            uint folderConst = 0x7A88FB59;
            uint folderKey = folderHash << 0x7;
            folderKey += folderHash;
            folderKey += folderConst;
            return folderKey;
        }

        public static uint DecryptRoutine(uint keyX, uint keyY, int offset, byte[] input, byte[] output)
        {
            for (int i = offset; i < input.Length; i += 4)
            {
                uint interval = keyX * KEY_CONST;
                uint encryptedWord = (uint)BitConverter.ToInt32(input, i);
                encryptedWord ^= keyX;
                byte[] decryptedBytes = BitConverter.GetBytes(encryptedWord);
                decryptedBytes.CopyTo(output, i);
                keyX = interval + keyY;
            }
            return keyX;
        }

        public static void Decrypt(string inFilename, string outFilename, Game game)
        {
            using (BufferedStream reader = new BufferedStream(File.Open(inFilename, FileMode.Open)))
            using (BufferedStream writer = new BufferedStream(File.Open(outFilename, FileMode.OpenOrCreate)))
            {
                byte[] rootTableEncrypted = new byte[16];
                reader.Read(rootTableEncrypted, 0, 16);
                uint rootKey = (uint)BitConverter.ToInt32(rootTableEncrypted, 0);
                uint keyX = rootKey;
                uint keyY = rootKey ^ 0xF0F0;
                byte[] rootTableDecrypted = new byte[16];
                keyX = DecryptRoutine(keyX, keyY, 4, rootTableEncrypted, rootTableDecrypted);
                writer.Write(rootTableDecrypted, 0, rootTableDecrypted.Length);

                int directoryCount = BitConverter.ToInt16(rootTableDecrypted, 8);
                rootTableEncrypted = new byte[directoryCount * game.RootEntryLength];
                rootTableDecrypted = new byte[directoryCount * game.RootEntryLength];
                reader.Read(rootTableEncrypted, 0, rootTableEncrypted.Length);
                keyX = DecryptRoutine(keyX, keyY, 0, rootTableEncrypted, rootTableDecrypted);
                writer.Write(rootTableDecrypted, 0, rootTableDecrypted.Length);
                Directory[] directories = new Directory[directoryCount];
                for (int i = 0; i < directoryCount; i++)
                {
                    byte[] directoryName = new byte[game.DirectoryNameLength];
                    for (int j = 0; j < game.DirectoryNameLength; j++)
                    {
                        directoryName[j] = rootTableDecrypted[(i * game.RootEntryLength) + j];
                    }
                    uint folderHash;
                    if (game.GameType == GameType.Zoe2)
                    {
                        folderHash = HashFolderNameZOE(directoryName);
                    }
                    else
                    {
                        folderHash = HashFolderName(directoryName);
                    }
                    uint folderKeyX = MakeFolderKeyX(folderHash, rootKey);
                    uint folderKeyY = MakeFolderKeyY(folderHash);
                    uint offset = BitConverter.ToUInt32(rootTableDecrypted, (i * game.RootEntryLength) + game.DirectoryNameLength);
                    offset *= 2048;
                    directories[i] = new Directory(folderHash, folderKeyX, folderKeyY, System.Text.Encoding.Default.GetString(directoryName).TrimEnd('\0'), offset);
                }

                List<DirectoryFile> fileList = new List<DirectoryFile>();
                for (int i = 0; i < directories.Length; i++)
                {
                    reader.Seek(directories[i].Offset, SeekOrigin.Begin);
                    writer.Seek(directories[i].Offset, SeekOrigin.Begin);

                    byte[] folderEncryptedEntries = new byte[4];
                    byte[] folderDecryptedEntries = new byte[4];
                    reader.Read(folderEncryptedEntries, 0, 4);
                    uint nextKeyX = DecryptRoutine(directories[i].KeyX, directories[i].KeyY, 0, folderEncryptedEntries, folderDecryptedEntries);
                    int tableLength = BitConverter.ToInt32(folderDecryptedEntries, 0);
                    byte[] folderTableEncrypted = new byte[tableLength * game.DirectoryEntryLength];
                    byte[] folderTableDecrypted = new byte[tableLength * game.DirectoryEntryLength];
                    reader.Read(folderTableEncrypted, 0, tableLength * game.DirectoryEntryLength);
                    DecryptRoutine(nextKeyX, directories[i].KeyY, 0, folderTableEncrypted, folderTableDecrypted);
                    byte[] joinedDecryptedTable = new byte[tableLength * game.DirectoryEntryLength + 4];
                    folderDecryptedEntries.CopyTo(joinedDecryptedTable, 0);
                    folderTableDecrypted.CopyTo(joinedDecryptedTable, 4);
                    directories[i].DirectoryTable = joinedDecryptedTable;
                    writer.Write(joinedDecryptedTable, 0, joinedDecryptedTable.Length);

                    uint directoryLength;
                    if (i < directories.Length - 1)
                    {
                        directoryLength = directories[i + 1].Offset - directories[i].Offset;
                    }
                    else
                    {
                        directoryLength = (uint)reader.Length - directories[i].Offset;
                    }
                    fileList.AddRange(directories[i].GetFilesFromTable(directoryLength, game.DirectoryEntryLength));
                }
                //Now we have the list of files iterate through them and if needed decrypt, otherwise copy. Decryption done!!
                for (int i = 0; i < fileList.Count; i++)
                {
                    uint wordFileLength = ((uint)Math.Ceiling(fileList[i].Length / (double)4)) * 4;
                    byte[] fileData = new byte[wordFileLength];
                    reader.Seek(fileList[i].Offset, SeekOrigin.Begin);
                    writer.Seek(fileList[i].Offset, SeekOrigin.Begin);
                    reader.Read(fileData, 0, fileData.Length);

                    if (fileList[i].Crypted)
                    {
                        byte[] decryptedFileData = new byte[wordFileLength];

                        uint fileKey = BitConverter.ToUInt16(fileData, 0);
                        fileKey ^= 0x9385;
                        uint fileKeyY = fileKey * 0x116;
                        uint fileKeyX = fileKey ^ 0x6576;
                        fileKeyX <<= 0x10;
                        fileKeyX |= fileKey;
                        DecryptRoutine(fileKeyX, fileKeyY, 0, fileData, decryptedFileData);
                        decryptedFileData[0] = 0x78;
                        decryptedFileData[1] = 0x9c;
                        writer.Write(decryptedFileData, 0, fileData.Length);
                    }
                    else
                    {
                        writer.Write(fileData, 0, fileData.Length);
                    }
                }
            }
        }
    }
}
