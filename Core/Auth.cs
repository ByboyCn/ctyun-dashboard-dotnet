using System.Security.Cryptography;

namespace CtyunDashboard;

/// <summary>口令散列：PBKDF2-HMAC-SM3（国密），会话签发/校验。</summary>
public static class Auth
{
    public const int Iterations = 100_000;

    public static (string Hash, string Salt) HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var dk = Gm.Pbkdf2Sm3(password, salt, Iterations, 32);
        return (Convert.ToBase64String(dk), Convert.ToBase64String(salt));
    }

    public static bool Verify(string password, string hash, string salt)
    {
        try
        {
            var expect = Convert.FromBase64String(hash);
            var dk = Gm.Pbkdf2Sm3(password, Convert.FromBase64String(salt), Iterations, expect.Length);
            return CryptographicOperations.FixedTimeEquals(dk, expect);
        }
        catch { return false; }
    }
}
