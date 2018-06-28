// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

namespace WindowsPdbReader
{
    internal sealed class MsfDirectory
    {
        private readonly DataStream[] streams;

        public MsfDirectory(PageAwarePdbReader reader, int pageSize, int directorySize, int[] directoryRoot)
        {
            int numPages = reader.PagesFromSize(directorySize);

            var pages = new int[numPages];
            var buf = MemoryMarshal.Cast<int, byte>(pages);

            int offset = 0;
            int pagesPerPage = pageSize / 4;
            int pagesToGo = numPages;
            for (int i = 0; i < directoryRoot.Length; ++i)
            {
                int pagesInThisPage = pagesToGo <= pagesPerPage ? pagesToGo : pagesPerPage;
                reader.Seek(directoryRoot[i], 0);
                reader.Stream.Read(buf.Slice(offset, pagesInThisPage * 4));
                pagesToGo -= pagesInThisPage;
            }

            var stream = new DataStream(directorySize, pages);
            var buffer = new byte[directorySize];
            stream.Read(reader, buffer);

            offset = 0;
            int count = InterpretInt32(buffer, ref offset);

            // 4..n
            int[] sizes = new int[count];

            for (int i = 0; i < sizes.Length; ++i)
            {
                sizes[i] = InterpretInt32(buffer, ref offset);
            }

            streams = new DataStream[count];

            for (int i = 0; i < count; i++)
            {
                if (sizes[i] <= 0)
                {
                    streams[i] = new DataStream();
                }
                else
                {
                    int dataStreamPages = reader.PagesFromSize(sizes[i]);
                    if (dataStreamPages > 0)
                    {
                        var dsPages = new int[dataStreamPages];
                        for (int j = 0; j < dataStreamPages; ++j)
                        {
                            dsPages[j] = InterpretInt32(buffer, ref offset);
                        }

                        streams[i] = new DataStream(sizes[i], dsPages);
                    }
                    else
                    {
                        streams[i] = new DataStream(sizes[i], null);
                    }
                }
            }
        }

        public DataStream[] Streams => this.streams;

        private static int InterpretInt32(Span<byte> buffer, ref int offset)
        {
            var retval = (int)((buffer[offset + 0] & 0xFF) |
                         (buffer[offset + 1] << 8) |
                         (buffer[offset + 2] << 16) |
                         (buffer[offset + 3] << 24));
            offset += 4;
            return retval;
        }
    }
}