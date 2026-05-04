param(
    [string]$Path = 'F:\development\steam\emulator_bot\OnLive\Microconsole\onlive.bin',
    [int]$Block = 65536  # 64 KB per row
)

$ErrorActionPreference = 'Stop'

$src = @"
using System;
using System.IO;
using System.Text;
public static class Mapper {
    public static string Map(string path, int block) {
        var sb = new StringBuilder();
        var buf = new byte[block];
        long pos = 0;
        long runStart = 0;
        char runChar = ' ';
        using(var fs = File.OpenRead(path)) {
            while(true) {
                int n = fs.Read(buf, 0, buf.Length);
                if(n <= 0) break;
                int zeros=0, ffs=0, ascii=0, nonprint=0;
                for(int i=0;i<n;i++) {
                    byte b = buf[i];
                    if(b==0) zeros++;
                    else if(b==0xFF) ffs++;
                    else if(b>=0x20 && b<0x7F) ascii++;
                    else nonprint++;
                }
                char c;
                if(zeros == n) c = '0';
                else if(ffs == n) c = 'F';
                else if(zeros > n*0.95) c = '.';
                else if(ffs > n*0.95) c = '~';
                else if(ascii > n*0.6) c = 'A';
                else c = '#';
                if(c != runChar) {
                    if(runChar != ' ') {
                        sb.AppendFormat("0x{0:X8} - 0x{1:X8}  {2}  ({3} blocks)\n",
                            runStart, pos-1, runChar, (pos-runStart)/block);
                    }
                    runChar = c;
                    runStart = pos;
                }
                pos += n;
                if(n < buf.Length) break;
            }
            sb.AppendFormat("0x{0:X8} - 0x{1:X8}  {2}  ({3} blocks)\n",
                runStart, pos-1, runChar, (pos-runStart)/block);
        }
        sb.Append("Legend: 0=all zero  F=all 0xFF  .=mostly zero  ~=mostly 0xFF  A=mostly ASCII  #=binary data\n");
        return sb.ToString();
    }
}
"@
Add-Type -TypeDefinition $src -Language CSharp
[Mapper]::Map($Path, $Block)
