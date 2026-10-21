using System.Security.Cryptography;
using System.Text;

namespace CtyunDashboard;

/// <summary>
/// 国密算法套件（纯托管实现，NativeAOT 安全）：
/// - SM3   哈希（GB/T 32905-2016）
/// - SM4   分组密码（GB/T 32907-2016），本工程使用 SM4-CBC
/// - HMAC-SM3 / PBKDF2-HMAC-SM3（口令散列）
/// - 凭据落盘格式：SM4-CBC 加密 + HMAC-SM3(encrypt-then-MAC)
/// 平台协议侧的 RSA/AES/MD5（官方报文要求）保持原样，不在国密替换范围。
/// </summary>
public static class Gm
{
    // ---------------- SM3 ----------------

    private static readonly uint[] Sm3Iv =
    [
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    ];

    private static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));

    public static byte[] Sm3Hash(ReadOnlySpan<byte> data)
    {
        // 填充：0x80 + 0... + 64bit 大端长度
        var bitLen = (ulong)data.Length * 8;
        var paddedLen = (data.Length + 9 + 63) / 64 * 64;
        var buf = new byte[paddedLen];
        data.CopyTo(buf);
        buf[data.Length] = 0x80;
        for (var i = 0; i < 8; i++) buf[paddedLen - 1 - i] = (byte)(bitLen >> (8 * i));

        var v = (uint[])Sm3Iv.Clone();
        var w = new uint[68];
        var w1 = new uint[64];

        for (var off = 0; off < paddedLen; off += 64)
        {
            for (var i = 0; i < 16; i++)
                w[i] = (uint)(buf[off + i * 4] << 24 | buf[off + i * 4 + 1] << 16 | buf[off + i * 4 + 2] << 8 | buf[off + i * 4 + 3]);
            for (var j = 16; j < 68; j++)
            {
                var x = w[j - 16] ^ w[j - 9] ^ Rotl(w[j - 3], 15);
                x = x ^ Rotl(x, 15) ^ Rotl(x, 23);
                w[j] = x ^ Rotl(w[j - 13], 7) ^ w[j - 6];
            }
            for (var j = 0; j < 64; j++) w1[j] = w[j] ^ w[j + 4];

            uint a = v[0], b = v[1], c = v[2], d = v[3], e = v[4], f = v[5], g = v[6], h = v[7];
            for (var j = 0; j < 64; j++)
            {
                var tj = j < 16 ? 0x79cc4519u : 0x7a879d8au;
                var ss1 = Rotl(Rotl(a, 12) + e + Rotl(tj, j % 32), 7);
                var ss2 = ss1 ^ Rotl(a, 12);
                uint ff = j < 16 ? a ^ b ^ c : (a & b) | (a & c) | (b & c);
                uint gg = j < 16 ? e ^ f ^ g : (e & f) | (~e & g);
                var tt1 = ff + d + ss2 + w1[j];
                var tt2 = gg + h + ss1 + w[j];
                d = c; c = Rotl(b, 9); b = a; a = tt1;
                h = g; g = Rotl(f, 19); f = e;
                e = tt2 ^ Rotl(tt2, 9) ^ Rotl(tt2, 17);
            }
            v[0] ^= a; v[1] ^= b; v[2] ^= c; v[3] ^= d;
            v[4] ^= e; v[5] ^= f; v[6] ^= g; v[7] ^= h;
        }

        var outBuf = new byte[32];
        for (var i = 0; i < 8; i++)
        {
            outBuf[i * 4] = (byte)(v[i] >> 24);
            outBuf[i * 4 + 1] = (byte)(v[i] >> 16);
            outBuf[i * 4 + 2] = (byte)(v[i] >> 8);
            outBuf[i * 4 + 3] = (byte)v[i];
        }
        return outBuf;
    }

    public static string Sm3Hex(string s) => Convert.ToHexString(Sm3Hash(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    /// <summary>启动自检：对齐 GB/T 32905-2016 标准向量。返回错误描述，null=通过。</summary>
    public static string? Sm3SelfTest()
    {
        var got = Sm3Hex("abc");
        const string want = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
        return got == want ? null : $"SM3 标准向量校验失败: got={got}";
    }

    // ---------------- HMAC-SM3 / PBKDF2 ----------------

    public static byte[] HmacSm3(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        const int block = 64;
        var k = key.ToArray();
        if (k.Length > block) k = Sm3Hash(k);
        var kip = new byte[block];
        var kop = new byte[block];
        k.CopyTo(kip, 0);
        k.CopyTo(kop, 0);
        for (var i = 0; i < block; i++) { kip[i] ^= 0x36; kop[i] ^= 0x5c; }
        return Sm3Hash([.. kop, .. Sm3Hash([.. kip, .. data])]);
    }

    /// <summary>PBKDF2-HMAC-SM3（口令散列用）。</summary>
    public static byte[] Pbkdf2Sm3(string password, byte[] salt, int iterations, int dkLen)
    {
        var pw = Encoding.UTF8.GetBytes(password);
        var result = new byte[dkLen];
        var block = 1;
        var filled = 0;
        while (filled < dkLen)
        {
            var be = BitConverter.GetBytes(block);
            if (BitConverter.IsLittleEndian) Array.Reverse(be);
            var u = HmacSm3(pw, [.. salt, .. be]);
            var t = (byte[])u.Clone();
            for (var i = 1; i < iterations; i++)
            {
                u = HmacSm3(pw, u);
                for (var j = 0; j < t.Length; j++) t[j] ^= u[j];
            }
            var n = Math.Min(t.Length, dkLen - filled);
            Array.Copy(t, 0, result, filled, n);
            filled += n;
            block++;
        }
        return result;
    }

    // ---------------- SM4 ----------------

    private static readonly byte[] Sbox =
    [
        0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
        0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
        0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
        0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
        0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
        0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
        0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
        0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
        0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
        0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
        0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
        0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
        0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
        0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
        0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
        0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
    ];

    private static readonly uint[] Fk = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

    private static readonly uint[] Ck =
    [
        0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279
    ];

    private static uint Tau(uint x) =>
        (uint)(Sbox[x >> 24] << 24 | Sbox[(x >> 16) & 0xFF] << 16 | Sbox[(x >> 8) & 0xFF] << 8 | Sbox[x & 0xFF]);

    private static uint TEnc(uint z) { var b = Tau(z); return b ^ Rotl(b, 2) ^ Rotl(b, 10) ^ Rotl(b, 18) ^ Rotl(b, 24); }
    private static uint TKey(uint z) { var b = Tau(z); return b ^ Rotl(b, 13) ^ Rotl(b, 23); }

    private static uint[] ExpandKey(ReadOnlySpan<byte> key)
    {
        var k = new uint[4];
        for (var i = 0; i < 4; i++)
            k[i] = (uint)(key[i * 4] << 24 | key[i * 4 + 1] << 16 | key[i * 4 + 2] << 8 | key[i * 4 + 3]) ^ Fk[i];
        var rk = new uint[32];
        for (var i = 0; i < 32; i++)
        {
            k[i & 3] ^= TKey(k[(i + 1) & 3] ^ k[(i + 2) & 3] ^ k[(i + 3) & 3] ^ Ck[i]);
            rk[i] = k[i & 3];
        }
        return rk;
    }

    private static void CryptBlock(uint[] rk, ReadOnlySpan<byte> input, Span<byte> output, bool decrypt)
    {
        Span<uint> s = stackalloc uint[4];
        for (var i = 0; i < 4; i++)
            s[i] = (uint)(input[i * 4] << 24 | input[i * 4 + 1] << 16 | input[i * 4 + 2] << 8 | input[i * 4 + 3]);
        for (var i = 0; i < 32; i++)
        {
            var rki = decrypt ? 31 - i : i;
            var nxt = s[0] ^ TEnc(s[1] ^ s[2] ^ s[3] ^ rk[rki]);
            s[0] = s[1]; s[1] = s[2]; s[2] = s[3]; s[3] = nxt;
        }
        for (var i = 0; i < 4; i++)
        {
            var w = s[3 - i];
            output[i * 4] = (byte)(w >> 24); output[i * 4 + 1] = (byte)(w >> 16);
            output[i * 4 + 2] = (byte)(w >> 8); output[i * 4 + 3] = (byte)w;
        }
    }

    /// <summary>SM4 标准向量自检（GB/T 32907-2016 附录 A 例 1 + 例 3）。返回错误描述，null=通过。</summary>
    public static string? Sm4SelfTest()
    {
        var key = Convert.FromHexString("0123456789abcdeffedcba9876543210");
        var pt = Convert.FromHexString("0123456789abcdeffedcba9876543210");
        var rk = ExpandKey(key);
        // 例 1：标准明文/密文（含全部 32 轮中间值可对齐 X_32=536E4246）
        var ct = new byte[16];
        CryptBlock(rk, pt, ct, false);
        var got = Convert.ToHexString(ct).ToLowerInvariant();
        const string want1 = "681edf34d206965e86b3e94f536e4246";
        if (got != want1) return $"SM4 标准向量校验失败: got={got}";
        // 例 3：明文迭代 100 万次
        var cur = (byte[])pt.Clone();
        var buf = new byte[16];
        for (var i = 0; i < 1_000_000; i++)
        {
            CryptBlock(rk, cur, buf, false);
            (cur, buf) = (buf, cur);
        }
        var got3 = Convert.ToHexString(cur).ToLowerInvariant();
        const string want3 = "595298c7c6fd271f0402f804c33d3f66";
        if (got3 != want3) return $"SM4 百万次迭代校验失败: got={got3}";
        var back = new byte[16];
        CryptBlock(rk, ct, back, true);
        return back.SequenceEqual(pt) ? null : "SM4 解密回环校验失败";
    }

    // ---------------- 组合：SM4-CBC + HMAC-SM3（encrypt-then-MAC） ----------------

    private static (byte[] Sm4Key, byte[] MacKey) Derive(byte[] master)
    {
        var enc = HmacSm3(master, "sm4-enc"u8);
        var mac = HmacSm3(master, "sm4-mac"u8);
        return (enc[..16], mac);
    }

    public static string Protect(byte[] master, byte[] plain)
    {
        var (sm4Key, macKey) = Derive(master);
        var iv = RandomNumberGenerator.GetBytes(16);
        var padded = Pad(plain);
        var ct = new byte[padded.Length];
        var prev = (Span<byte>)iv;
        var block = new byte[16];
        var rk = ExpandKey(sm4Key);
        for (var off = 0; off < padded.Length; off += 16)
        {
            for (var i = 0; i < 16; i++) block[i] = (byte)(padded[off + i] ^ prev[i]);
            var cur = new byte[16];
            CryptBlock(rk, block, cur, false);
            cur.CopyTo(ct, off);
            prev = cur;
        }
        var tag = HmacSm3(macKey, [.. iv, .. ct]);
        return "gm1." + Convert.ToBase64String([.. iv, .. tag, .. ct]);
    }

    public static byte[] Unprotect(byte[] master, string payload)
    {
        if (string.IsNullOrEmpty(payload) || !payload.StartsWith("gm1.")) return [];
        var raw = Convert.FromBase64String(payload[4..]);
        if (raw.Length < 49 || raw.Length % 16 != 1 % 16 + 48 - 48 && raw.Length < 49) return [];
        if ((raw.Length - 48) % 16 != 0) return [];
        var iv = raw[..16].ToArray();
        var tag = raw[16..48].ToArray();
        var ct = raw[48..];
        var (sm4Key, macKey) = Derive(master);
        var expect = HmacSm3(macKey, [.. iv, .. ct]);
        if (!CryptographicOperations.FixedTimeEquals(expect, tag)) return [];
        var rk = ExpandKey(sm4Key);
        var pt = new byte[ct.Length];
        var prev = (Span<byte>)iv;
        var block = new byte[16];
        for (var off = 0; off < ct.Length; off += 16)
        {
            CryptBlock(rk, ct.AsSpan(off), block, true);
            for (var i = 0; i < 16; i++) pt[off + i] = (byte)(block[i] ^ prev[i]);
            prev = ct.AsSpan(off, 16);
        }
        return Unpad(pt);
    }

    private static byte[] Pad(byte[] data)
    {
        var padLen = 16 - data.Length % 16;
        var outBuf = new byte[data.Length + padLen];
        data.CopyTo(outBuf, 0);
        for (var i = data.Length; i < outBuf.Length; i++) outBuf[i] = (byte)padLen;
        return outBuf;
    }

    private static byte[] Unpad(byte[] data)
    {
        if (data.Length == 0 || data.Length % 16 != 0) return [];
        var padLen = data[^1];
        if (padLen is < 1 or > 16) return [];
        for (var i = data.Length - padLen; i < data.Length; i++)
            if (data[i] != padLen) return [];
        return data[..^padLen];
    }
}
