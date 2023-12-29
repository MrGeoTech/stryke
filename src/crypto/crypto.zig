const std = @import("std");
const crypto = std.crypto;
const evp = @cImport({
    @cInclude("openssl/evp.h");
});
const rsa = @cImport({
    @cInclude("cryptopp/rsa.h");
});
const big = std.math.big;

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

test "CFB8Cipher" {
    std.testing.refAllDecls(CFB8Cipher);
    rsa.RSA;
}
