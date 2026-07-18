using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

if (args.Length < 3) { Console.WriteLine("usage: IconBuild src.jpg out.ico out-256.png"); return 1; }
var srcPath = args[0]; var icoPath = args[1]; var png256 = args[2];
int[] sizes = [16, 24, 32, 48, 64, 128, 256];
using var src = new Bitmap(srcPath);
var images = new List<byte[]>();
foreach (var s in sizes)
{
    using var bmp = new Bitmap(s, s, PixelFormat.Format32bppArgb);
    using var g = Graphics.FromImage(bmp);
    g.Clear(Color.Transparent);
    g.InterpolationMode = InterpolationMode.HighQualityBicubic;
    g.SmoothingMode = SmoothingMode.HighQuality;
    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
    g.DrawImage(src, 0, 0, s, s);
    if (s == 256) bmp.Save(png256, ImageFormat.Png);
    using var ms = new MemoryStream();
    bmp.Save(ms, ImageFormat.Png);
    images.Add(ms.ToArray());
}
using var fs = File.Create(icoPath);
using var bw = new BinaryWriter(fs);
bw.Write((short)0); bw.Write((short)1); bw.Write((short)images.Count);
int offset = 6 + 16 * images.Count;
for (int i = 0; i < images.Count; i++)
{
    int s = sizes[i];
    bw.Write((byte)(s >= 256 ? 0 : s));
    bw.Write((byte)(s >= 256 ? 0 : s));
    bw.Write((byte)0); bw.Write((byte)0);
    bw.Write((short)1); bw.Write((short)32);
    bw.Write(images[i].Length); bw.Write(offset);
    offset += images[i].Length;
}
foreach (var img in images) bw.Write(img);
Console.WriteLine("Wrote " + icoPath);
return 0;
