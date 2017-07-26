using System;

namespace MGDecrypt
{
    public enum GameType { Mgs2, Zoe2, Mgs3 };
    class Game
    {
        private static readonly Game Mgs2 = new Game(12, 8, 8, GameType.Mgs2);
        private static readonly Game Zoe2 = new Game(20, 16, 12, GameType.Zoe2);
        private static readonly Game Mgs3 = new Game(20, 16, 8, GameType.Mgs3);

        public int RootEntryLength { get; private set; }
        public int DirectoryNameLength { get; private set; }
        public int DirectoryEntryLength { get; private set; }
        public GameType GameType { get; private set; }

        private Game(int rootEntryLength, int directoryNameLength, int directoryEntryLength, GameType gameType)
        {
            RootEntryLength = rootEntryLength;
            DirectoryNameLength = directoryNameLength;
            DirectoryEntryLength = directoryEntryLength;
            GameType = GameType;
        }

        public static Game GetGameByName(string name)
        {
            switch (name)
            {
                case "-mgs2":
                    return Mgs2;
                case "-mgs3":
                    return Mgs3;
                case "-zoe2":
                    return Zoe2;
                default:
                    throw new NotImplementedException();
            }
        }
    }
}
