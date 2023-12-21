const std = @import("std");
const crypto = std.crypto;
const evp = @cImport({
    @cInclude("openssl/evp.h");
});

/// Zig wrapper for openssl cryptography
/// Should probably add some tests but I just spent the last week
/// trying to get cryptography so I'm just going to trust openssl
/// has got it for now
pub const CFB8Cipher = struct {
    encryption: *evp.EVP_CIPHER_CTX,
    decryption: *evp.EVP_CIPHER_CTX,

    pub fn init(key: [16]u8) !CFB8Cipher {
        var encryption = evp.EVP_CIPHER_CTX_new() orelse return error.CipherContextInitError;
        var decryption = evp.EVP_CIPHER_CTX_new() orelse return error.CipherContextInitError;

        if (evp.EVP_EncryptInit_ex(encryption, evp.EVP_aes_128_cfb8(), null, &key, &key) != 1)
            return error.EncryptionInitError;
        if (evp.EVP_DecryptInit_ex(decryption, evp.EVP_aes_128_cfb8(), null, &key, &key) != 1)
            return error.DecryptionInitError;

        return CFB8Cipher{
            .encryption = encryption,
            .decryption = decryption,
        };
    }

    pub fn deinit(self: *CFB8Cipher) void {
        evp.EVP_CIPHER_CTX_free(self.encryption);
        evp.EVP_CIPHER_CTX_free(self.decryption);
    }

    pub fn encrypt(self: *CFB8Cipher, dst: []u8, src: []const u8) !void {
        var len: c_int = @intCast(src.len);
        var out_len = len;
        if (evp.EVP_EncryptUpdate(self.encryption, dst.ptr, &out_len, src.ptr, len) != 0)
            return error.EncryptionError;
    }

    pub fn decrypt(self: *CFB8Cipher, dst: []u8, src: []const u8) !void {
        var len: c_int = @intCast(src.len);
        var out_len = len;
        if (evp.EVP_DecryptUpdate(self.decryption, dst.ptr, &out_len, src.ptr, len) != 0)
            return error.EncryptionError;
    }

    test "init" {
        const key: [16]u8 = undefined;
        const cipher = try CFB8Cipher.init(key);
        _ = cipher;
    }
};

pub const RSACipher = struct {
    pub const ASN1 = struct {
        length: usize,
        bytes: [256]u8,
    };
    asn1: ASN1,
    d: u1024,
    n: u1024,

    pub fn init() RSACipher {
        var e: usize = 65537;
        var p = genRandPrime(u512);
        var q = genRandPrime(u512);

        var n: u1024 = @as(u1024, q) * @as(u1024, p);

        p -= 1;
        q -= 1;

        p = lcm(q, p);

        var d = modInv(e, p);

        // ASN1

        const prefix = [_]u8{
            0x30, 0x81, 0x9F, 0x30, 0x0D,
            0x06, 0x09, 0x2A, 0x86, 0x48,
            0x86, 0xF7, 0x0D, 0x01, 0x01,
            0x01, 0x05, 0x00, 0x03, 0x81,
            0x8D, 0x00, 0x30, 0x81, 0x89,
            0x02, 0x81, 0x81,
        };

        const suffix = [_]u8{
            0x02, 0x03, 0x01, 0x00, 0x01,
        };

        const asn1 = ASN1{
            .length = prefix.len + 129 + suffix.len,
            .bytes = undefined,
        };

        @memcpy(asn1.bytes[0..prefix.len], prefix[0..]);
        std.mem.writeInt(@TypeOf(n), asn1.bytes[prefix.len + 1 .. prefix.len + 129], n, .big);
        @memcpy(asn1.bytes[prefix.len], suffix[0..]);

        return RSACipher{
            .asn1 = asn1,
            .d = d,
            .n = n,
        };
    }

    pub fn decrypt(self: *RSACipher, dst: []u8, src: []const u8) void {
        var c = std.mem.readInt(, bytes: *const [@divExact(@typeInfo(T).Int.bits, 8)]u8, endian: Endian)
    }

    /// Generates a secure random prime number
    /// Uses inefficient algorithm
    fn genRandPrime(comptime T: type) T {
        var prime = crypto.random.int(T);
        // Make sure it odd
        prime |= 1;
        // Make sure top two bits are 1 so the product is the correct bit length
        prime |= 0xC0 << (@bitSizeOf(T) - 8);

        // Getting next prime number
        // Probably uses a really bad algorithm but it only gets executed
        // once so doesn't need to be perfect
        // Could be a good first commit to look at GMPs implementation and make this better (hint hint)
        while (!isPrime(prime)) {
            prime += 1;
        }

        return prime;
    }

    fn isPrime(number: anytype) bool {
        for (2..number) |i| {
            if (number % i == 0) return false;
        }
        return true;
    }

    /// Gets the least common multiple of the two numbers
    /// Uses inefficient algorithm
    fn lcm(num1: anytype, num2: @TypeOf(num1)) @TypeOf(num1) {
        if (num1 == 0 or num2 == 0) return 0;
        const max = if (num1 >= num2) num1 else num2;
        const min = if (num1 >= num2) num2 else num1;
        var multiple = max;
        while (multiple % min != 0) {
            multiple += max;
        }
        return multiple;
    }

    /// Computes the modular inverse of num1 and num2
    /// Uses inefficient algorithm
    fn modInv(num1: anytype, num2: @TypeOf(num1)) @TypeOf(num1) {
        for (1..num2) |i| {
            if (((num1 % num2) * (i % num2)) % num2 == 1)
                return i;
        }
        return 1;
    }
};

test "CFB8Cipher" {
    std.testing.refAllDecls(CFB8Cipher);
}
