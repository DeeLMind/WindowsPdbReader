// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace WindowsPdbReader
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("WindowsPdbReader [PdbFile] [MethodToken] [ILOffset]");
                return;
            }

            using (var fs = new FileStream(args[0], FileMode.Open, FileAccess.Read))
            {
                ReadPdbHeader(fs, out  var pageSize, out var freePageMap, out var pagesUsed, out var directorySize, out var zero);

                int directoryPages = ((((directorySize + pageSize - 1) / pageSize) * 4) + pageSize - 1) / pageSize;

                var directoryRoot = new int[directoryPages];
                fs.Read(MemoryMarshal.Cast<int, byte>(directoryRoot));

                var pageAwarePdbReader = new PageAwarePdbReader(fs, pageSize);

                var msf = new MsfDirectory(pageAwarePdbReader, pageSize, directorySize, directoryRoot);
                var size = msf.Streams[1].Length;
                var nameIndexByteArray = new byte[size];
                msf.Streams[1].Read(pageAwarePdbReader, nameIndexByteArray);

                var nameIndex = LoadNameIndex(nameIndexByteArray, out int age, out Guid guid);
                if (!nameIndex.TryGetValue("/NAMES", out var nameStream))
                {
                    throw new Exception("Could not find the '/NAMES' stream: the PDB file may be a public symbol file instead of a private symbol file");
                }

                var nameStreamByteArray = new byte[msf.Streams[nameStream].Length];
                msf.Streams[nameStream].Read(pageAwarePdbReader, nameStreamByteArray);

                var names = LoadNameStream(nameStreamByteArray);

                string sourceServerData = string.Empty;

                if (nameIndex.TryGetValue("SRCSRV", out var srcsrvStream))
                {
                    DataStream dataStream = msf.Streams[srcsrvStream];
                    byte[] bytes = new byte[dataStream.Length];
                    dataStream.Read(pageAwarePdbReader, bytes);
                    sourceServerData = Encoding.UTF8.GetString(bytes, 0, bytes.Length);
                }

                var dbiArray = new byte[msf.Streams[3].Length];
                msf.Streams[3].Read(pageAwarePdbReader, dbiArray);

                var list = LoadDbiStream(dbiArray, out DbiDbgHdr header);
                LoadFunctions(list, msf, pageAwarePdbReader, names, uint.Parse(args[1]), uint.Parse(args[2]), out string sourceFile, out int sourceLine, out int sourceColumn);

                Console.WriteLine($"File: {sourceFile ?? string.Empty}, Line: {sourceLine}, Column: {sourceColumn}");
            }
        }

        private static void LoadFunctions(List<DbiModuleInfo> modules, MsfDirectory dir, PageAwarePdbReader reader, Dictionary<int, string> names, uint token, uint iloffset, out string sourceFile, out int sourceLine, out int sourceColumn)
        {
            sourceFile = null;
            sourceLine = 0;
            sourceColumn = 0;

            for (int m = 0; m < modules.Count; ++m)
            {
                var module = modules[m];
                if (module.stream > 0)
                {
                    byte[] bits = default;
                    try
                    {
                        var stream = dir.Streams[module.stream];
                        bits = ArrayPool<byte>.Shared.Rent(stream.Length);
                        stream.Read(reader, bits);

                        if (TryGetManProcSym(bits, module, token, out ManProcSym sym))
                        {
                            GetLineNumberInformation(bits, module, sym.off + iloffset, names, out sourceFile, out sourceLine, out sourceColumn);
                            Console.WriteLine($"Token: {sym.token}, Start: {sym.off:X8}, End: {sym.off+sym.len:X8}, Source: {sourceFile}, Line: {sourceLine}, Column: {sourceColumn}");
                        }
                    }
                    finally
                    {
                        if (bits != null)
                        {
                            ArrayPool<byte>.Shared.Return(bits);
                        }
                    }
                }
            }
        }

        private static bool TryGetManProcSym(byte[] bits, DbiModuleInfo module, uint token, out ManProcSym proc)
        {
            int offset = 0;
            int sig = InterpretInt32(bits, ref offset);

            if (sig != 4)
            {
                throw new Exception($"Invalid signature. (sig={sig})");
            }

            while (offset < module.cbSyms)
            {
                ushort siz = InterpretUInt16(bits, ref offset);
                int stop = offset + siz;
                ushort rec = InterpretUInt16(bits, ref offset);

                switch ((SYM) rec)
                {
                    case SYM.S_GMANPROC:
                    case SYM.S_LMANPROC:
                    {
                        InterpretStruct(bits, out proc, ref offset);

                        if (proc.token == token)
                        {
                            return true;
                        }

                        SkipCString(bits, ref offset);

                        break;
                    }
                }

                offset = stop;
            }

            proc = new ManProcSym();
            return false;
        }

        private static void LoadFunctionsInner(byte[] bits, DbiModuleInfo module, string moduleName, Dictionary<int, string> names, Dictionary<string, int> nameIndex)
        {
            int offset = 0;
            int sig = InterpretInt32(bits, ref offset);

            if (sig != 4)
            {
                throw new Exception($"Invalid signature. (sig={sig})");
            }

            while (offset < module.cbSyms)
            {
                ushort siz = InterpretUInt16(bits, ref offset);
                int stop = offset + siz;
                ushort rec = InterpretUInt16(bits, ref offset);

                switch ((SYM) rec)
                {
                    case SYM.S_GMANPROC:
                    case SYM.S_LMANPROC:
                    {
                        ManProcSym proc;

                        proc.parent = InterpretUInt32(bits, ref offset);
                        proc.end = InterpretUInt32(bits, ref offset);
                        proc.next = InterpretUInt32(bits, ref offset);
                        proc.len = InterpretUInt32(bits, ref offset);
                        proc.dbgStart = InterpretUInt32(bits, ref offset);
                        proc.dbgEnd = InterpretUInt32(bits, ref offset);
                        proc.token = InterpretUInt32(bits, ref offset);
                        proc.off = InterpretUInt32(bits, ref offset);
                        proc.seg = InterpretUInt16(bits, ref offset);
                        proc.flags = 0; offset++;
                        proc.retReg = InterpretUInt16(bits, ref offset);
                        var procName = ReadCString(bits, ref offset);

                        Console.WriteLine($"Module: {moduleName}, Name: {procName}, Token: {proc.token}, Seg: {proc.seg}, Offset: {proc.off}, Len: {proc.len}");

                        //if (false)
                        {
                            offset = module.cbSyms + module.cbOldLines;
                            var limit = offset + module.cbLines;

                            while (offset < limit)
                            {
                                int sig2 = InterpretInt32(bits, ref offset);
                                int siz2 = InterpretInt32(bits, ref offset);
                                int endSym = offset + siz2;

                                switch ((DEBUG_S_SUBSECTION)sig2)
                                {
                                    case DEBUG_S_SUBSECTION.LINES:
                                    {
                                        InterpretStruct(bits, out CV_LineSection sec, ref offset);
                                        InterpretStruct(bits, out CV_SourceFile file, ref offset);

                                        Console.WriteLine($"  File: {file.index}, {sec.sec:X8}:{sec.off:X8}-{sec.off+sec.cod:X8}, line/addr pairs = {file.count}");

                                        int plin = offset;
                                        int pcol = offset + 8 * (int) file.count;

                                        for (int i = 0; i < file.count; i++)
                                        {
                                            CV_Line line;
                                            CV_Column column = new CV_Column();

                                            offset = plin + 8 * i;
                                            line.offset = InterpretUInt32(bits, ref offset);
                                            line.flags = InterpretUInt32(bits, ref offset);

                                            uint lineBegin = line.flags & (uint) CV_Line_Flags.linenumStart;
                                            uint delta = (line.flags & (uint) CV_Line_Flags.deltaLineEnd) >> 24;

                                            if ((sec.flags & 1) != 0)
                                            {
                                                offset = pcol + 4 * i;
                                                column.offColumnStart = InterpretUInt16(bits, ref offset);
                                                column.offColumnEnd = InterpretUInt16(bits, ref offset);
                                            }

                                            Console.WriteLine();
                                            Console.Write($"     {lineBegin}:{column.offColumnStart}    -   {lineBegin + delta}:{column.offColumnEnd}    {sec.off+line.offset:X8}");
                                        }

                                        Console.WriteLine();

                                        break;
                                    }

                                    case DEBUG_S_SUBSECTION.FILECHKSMS:
                                    {
                                        while (offset < limit)
                                        {
                                            InterpretStruct(bits, out CV_FileCheckSum chk, ref offset);
                                            offset += chk.len;

                                            string name = (string)names[(int)chk.name];

                                            Guid doctypeGuid = new Guid(1518771467, 26129, 4563, 189, 42, 0, 0, 248, 8, 73, 189);
                                            Guid languageGuid = Guid.Empty;
                                            Guid vendorGuid = Guid.Empty;
                                            Guid checksumAlgoGuid = Guid.Empty;
                                            byte[] checksum = null;

                                            if (nameIndex.TryGetValue("/SRC/FILES/" + name, out int guidStream))
                                            {
                                                Console.WriteLine($"File: {name}");
                                            }

                                            Alignment(4, ref offset);
                                        }

                                        break;
                                    }
                                }

                                offset = endSym;
                            }
                        }

                        break;
                    }
                }
            }
        }

        private static void GetLineNumberInformation(byte[] bits, DbiModuleInfo module, uint functionOffset, Dictionary<int, string> names, out string sourceFile, out int sourceLine, out int sourceColumn)
        {
            sourceFile = null;
            sourceLine = 0;
            sourceColumn = 0;

            int offset = module.cbSyms + module.cbOldLines;
            var limit = offset + module.cbLines;

            while (offset < limit)
            {
                int sig = InterpretInt32(bits, ref offset);
                int siz = InterpretInt32(bits, ref offset);
                int endSym = offset + siz;

                switch ((DEBUG_S_SUBSECTION)sig)
                {
                    case DEBUG_S_SUBSECTION.LINES:
                    {
                        InterpretStruct(bits, out CV_LineSection sec, ref offset);

                        if (functionOffset >= sec.off && functionOffset <= sec.off + sec.cod)
                        {
                            InterpretStruct(bits, out CV_SourceFile file, ref offset);

                            int plin = offset;
                            int pcol = offset + 8 * (int)file.count;

                            for (int i = 0; i < file.count; i++)
                            {
                                CV_Line line;
                                CV_Column column = new CV_Column();

                                offset = plin + 8 * i;
                                line.offset = InterpretUInt32(bits, ref offset);
                                line.flags = InterpretUInt32(bits, ref offset);

                                uint lineBegin = line.flags & (uint)CV_Line_Flags.linenumStart;

                                if ((sec.flags & 1) != 0)
                                {
                                    offset = pcol + 4 * i;
                                    column.offColumnStart = InterpretUInt16(bits, ref offset);
                                    column.offColumnEnd = InterpretUInt16(bits, ref offset);
                                }

                                sourceLine = (int)lineBegin;
                                sourceColumn = column.offColumnStart;
                            }
                        }

                        break;
                    }

                    case DEBUG_S_SUBSECTION.FILECHKSMS:
                    {
                        while (offset < limit)
                        {
                            InterpretStruct(bits, out CV_FileCheckSum chk, ref offset);
                            offset += chk.len;

                            sourceFile = names[(int)chk.name];

                            Alignment(4, ref offset);
                        }

                        break;
                    }
                }

                offset = endSym;
            }
        }

        private static List<DbiModuleInfo> LoadDbiStream(byte[] bits, out DbiDbgHdr header)
        {
            int offset = 0;

            InterpretStruct(bits, out DbiHeader dbiHeader, ref offset);

            var list = new List<DbiModuleInfo>();

            int end = offset + dbiHeader.gpmodiSize;
            while (offset < end)
            {
                InterpretStruct(bits, out DbiModuleInfo moduleInfo, ref offset);
                SkipCString(bits, ref offset); // moduleName
                SkipCString(bits, ref offset); // objectName
                Alignment(4, ref offset);

                list.Add(moduleInfo);
            }

            if (offset != end)
            {
                throw new Exception($"Error reading DBI stream, pos={offset} != {end}");
            }

            // Skip the Section Contribution substream.
            offset += dbiHeader.secconSize;

            // Skip the Section Map substream.
            offset += dbiHeader.secmapSize;

            // Skip the File Info substream.
            offset += dbiHeader.filinfSize;

            // Skip the TSM substream.
            offset += dbiHeader.tsmapSize;

            // Skip the EC substream.
            offset += dbiHeader.ecinfoSize;

            // Read the optional header.
            end = offset + dbiHeader.dbghdrSize;
            if (dbiHeader.dbghdrSize > 0)
            {
                InterpretStruct(bits, out header, ref offset);
            }
            else
            {
                header = new DbiDbgHdr();
            }

            offset = end;

            return list;
        }

        private static Dictionary<int, string> LoadNameStream(Span<byte> bits)
        {
            var result = new Dictionary<int, string>();

            int offset = 0;

            uint sig = InterpretUInt32(bits, ref offset);
            int ver = InterpretInt32(bits, ref offset);

            if (sig != 0xeffeeffe || ver != 1)
            {
                throw new Exception($"Unsupported Name Stream version.(sig={sig:x8}, ver={ver})");
            }

            int buf = InterpretInt32(bits, ref offset);
            int beg = offset;
            int nxt = offset + buf;
            offset = nxt;

            // Read hash table.
            int siz = InterpretInt32(bits, ref offset);

            for (int i = 0; i < siz; i++)
            {
                int ni = InterpretInt32(bits, ref offset);

                if (ni != 0)
                {
                    int saved = offset;
                    offset = beg + ni;
                    var name = ReadCString(bits, ref offset);
                    offset = saved;

                    result.Add(ni, name);
                }
            }

            return result;
        }

        private static Dictionary<string, int> LoadNameIndex(Span<byte> bits, out int age, out Guid guid)
        {
            var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            int offset = 0;

            int ver = InterpretInt32(bits, ref offset);
            int sig = InterpretInt32(bits, ref offset);

            age = InterpretInt32(bits, ref offset);
            InterpretGuid(bits, out guid, ref offset);

            int buf = InterpretInt32(bits, ref offset);

            int beg = offset;
            int nxt = offset + buf;

            offset = nxt;

            int cnt = InterpretInt32(bits, ref offset);
            int max = InterpretInt32(bits, ref offset);

            var present = new uint[InterpretInt32(bits, ref offset)];
            for (int i = 0; i < present.Length; ++i)
            {
                present[i] = InterpretUInt32(bits, ref offset);
            }

            var deleted = new uint[InterpretInt32(bits, ref offset)];
            for (int i = 0; i < deleted.Length; ++i)
            {
                deleted[i] = InterpretUInt32(bits, ref offset);
            }

            int j = 0;
            for (int i = 0; i < max; i++)
            {
                if (IsSet(i, present))
                {
                    int ns = InterpretInt32(bits, ref offset);
                    int ni = InterpretInt32(bits, ref offset);

                    int saved = offset;
                    offset = beg + ns;
                    var name = ReadCString(bits, ref offset);
                    offset = saved;

                    result.Add(name.ToUpperInvariant(), ni);
                    j++;
                }
            }

            if (j != cnt)
            {
                throw new Exception($"Count mismatch. ({j} != {cnt})");
            }

            return result;
        }

        private static void Alignment(int alignment, ref int offset)
        {
            while (offset % alignment != 0)
            {
                offset++;
            }
        }

        private static void SkipCString(Span<byte> buffer, ref int offset)
        {
            int len = 0;

            while (offset + len < buffer.Length && buffer[offset + len] != 0)
            {
                len++;
            }

            offset += len + 1;
        }

        private static string ReadCString(Span<byte> buffer, ref int offset)
        {
            int len = 0;

            while (offset + len < buffer.Length && buffer[offset + len] != 0)
            {
                len++;
            }

            string value = Encoding.UTF8.GetString(buffer.Slice(offset, len));

            offset += len + 1;
            return value;
        }

        private static bool IsSet(int index, uint[] words)
        {
            int word = index / 32;

            if (word >= words.Length)
            {
                return false;
            }

            return (words[word] & ((uint)1 << (index % 32))) != 0;
        }

        private static void ReadPdbHeader(Stream stream, out int pageSize, out int freePageMap, out int pagesUsed, out int directorySize, out int zero)
        {
            ReadOnlySpan<byte> pdbMagic = new byte[] {
                0x4D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, // "Microsof"
                0x74, 0x20, 0x43, 0x2F, 0x43, 0x2B, 0x2B, 0x20, // "t C/C++ "
                0x4D, 0x53, 0x46, 0x20, 0x37, 0x2E, 0x30, 0x30, // "MSF 7.00"
                0x0D, 0x0A, 0x1A, 0x44, 0x53, 0x00, 0x00, 0x00  // "^^^DS^^^"
            };

            Span<byte> fileMagic = stackalloc byte[32];
            stream.Read(fileMagic);

            if (fileMagic.SequenceEqual(pdbMagic))
            {
                Span<byte> ss2 = stackalloc byte[20];
                stream.Read(ss2);

                pageSize = InterpretInt32X(ss2, 0);
                freePageMap = InterpretInt32X(ss2, 4);
                pagesUsed = InterpretInt32X(ss2, 8);
                directorySize = InterpretInt32X(ss2, 12);
                zero = InterpretInt32X(ss2, 16);

                int directoryPages = ((((directorySize + pageSize - 1) / pageSize) * 4) + pageSize - 1) / pageSize;
                return;
            }

            throw new Exception("sdd");
        }

        private static void InterpretStruct<T>(byte[] data, out T value, ref int offset) where T : unmanaged
        {
            int size = Marshal.SizeOf<T>();
            value = MemoryMarshal.Cast<byte, T>(new Span<byte>(data, offset, size))[0]; // https://github.com/dotnet/corefx/issues/30613
            offset += size;
        }

        private static int InterpretInt32X(Span<byte> buffer, int offset)
        {
            return ((buffer[offset + 0] & 0xFF) |
                          (buffer[offset + 1] << 8) |
                          (buffer[offset + 2] << 16) |
                          (buffer[offset + 3] << 24));
        }

        private static uint InterpretUInt32(Span<byte> buffer, ref int offset)
        {
            uint retval = (uint)((buffer[offset + 0] & 0xFF) |
                          (buffer[offset + 1] << 8) |
                          (buffer[offset + 2] << 16) |
                          (buffer[offset + 3] << 24));

            offset += 4;
            return retval;
        }

        private static int InterpretInt32(Span<byte> buffer, ref int offset)
        {
            var retval = ((buffer[offset + 0] & 0xFF) |
                         (buffer[offset + 1] << 8) |
                         (buffer[offset + 2] << 16) |
                         (buffer[offset + 3] << 24));

            offset += 4;
            return retval;
        }

        private static void InterpretGuid(Span<byte> buffer, out Guid retval, ref int offset)
        {
            retval = new Guid(buffer.Slice(offset, 16));
            offset += 16;
        }

        private static ushort InterpretUInt16(Span<byte> buffer, ref int offset)
        {
            var retval = (ushort)((buffer[offset + 0] & 0xFF) |
                             (buffer[offset + 1] << 8));
            offset += 2;
            return retval;
        }

        private static string ReadString(Span<byte> buffer, ref int offset)
        {
            int len = 0;
            while (offset + len < buffer.Length && buffer[offset + len] != 0)
            {
                len += 2;
            }

            var result = Encoding.Unicode.GetString(buffer.Slice(offset, len));
            offset += len + 2;
            return result;
        }
    }
}