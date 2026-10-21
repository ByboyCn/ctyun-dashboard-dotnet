using System.Security.Cryptography;
using System.Text;

namespace CtyunDashboard.CtYun;

/// <summary>天翼云官方协议加密原语（对齐 pc.ctyun.cn 前端逆向，平台要求，非国密范围）。</summary>
public static class CyCrypto
{
    // AES-CBC, key=UTF8(evalue), IV=全零16字节, PKCS7, base64
    public static string AesCbcEncryptToB64(string plain, string key)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = new byte[16];
        using var enc = aes.CreateEncryptor();
        var pt = Encoding.UTF8.GetBytes(plain);
        return Convert.ToBase64String(enc.TransformFinalBlock(pt, 0, pt.Length));
    }

    public static string AesCbcDecryptFromB64(string b64, string key)
    {
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        aes.IV = new byte[16];
        using var dec = aes.CreateDecryptor();
        var ct = Convert.FromBase64String(b64);
        return Encoding.UTF8.GetString(dec.TransformFinalBlock(ct, 0, ct.Length));
    }

    public static string Md5Hex(string s) => Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
    public static string Sha256Hex(string s) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    public static (string spkiB64, RSA rsa) GenRsaKeyPair()
    {
        var rsa = RSA.Create(2048);
        return (Convert.ToBase64String(rsa.ExportSubjectPublicKeyInfo()), rsa);
    }

    public static byte[] RsaDecryptFlexible(RSA rsa, byte[] data)
    {
        foreach (var padding in new[] { RSAEncryptionPadding.OaepSHA512, RSAEncryptionPadding.OaepSHA256, RSAEncryptionPadding.Pkcs1 })
        {
            try { return rsa.Decrypt(data, padding); }
            catch { }
        }
        throw new CryptographicException("RSA decrypt failed with all padding variants");
    }

    // CLINK ticket：162B DER SPKI（RSA-1024），OAEP-SHA1
    public static byte[] RsaEncryptTicketSpki(byte[] spki, byte[] password)
    {
        using var rsa = RSA.Create();
        rsa.ImportSubjectPublicKeyInfo(spki, out _);
        return rsa.Encrypt(password, RSAEncryptionPadding.OaepSHA1);
    }
}
