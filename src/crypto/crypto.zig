const std = @import("std");
const crypto = std.crypto;
const openssl = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/aes.h");
});
const big = std.math.big;

/// Zig wrapper for openssl cryptography
/// Should probably add some tests but I just spent the last week
/// trying to get cryptography so I'm just going to trust openssl
/// has got it for now
pub const CFB8Cipher = struct {
    encryption: *openssl.EVP_CIPHER_CTX,
    decryption: *openssl.EVP_CIPHER_CTX,

    pub fn init(key: [16]u8) !CFB8Cipher {
        var encryption = openssl.EVP_CIPHER_CTX_new() orelse return error.CipherContextInitError;
        var decryption = openssl.EVP_CIPHER_CTX_new() orelse return error.CipherContextInitError;

        if (openssl.EVP_EncryptInit_ex(encryption, openssl.EVP_aes_128_cfb8(), null, &key, &key) != 1)
            return error.EncryptionInitError;
        if (openssl.EVP_DecryptInit_ex(decryption, openssl.EVP_aes_128_cfb8(), null, &key, &key) != 1)
            return error.DecryptionInitError;

        return CFB8Cipher{
            .encryption = encryption,
            .decryption = decryption,
        };
    }

    pub fn deinit(self: *CFB8Cipher) void {
        openssl.EVP_CIPHER_CTX_free(self.encryption);
        openssl.EVP_CIPHER_CTX_free(self.decryption);
    }

    pub fn encrypt(self: *CFB8Cipher, dst: []u8, src: []const u8) !void {
        var len: c_int = @intCast(src.len);
        var out_len = len;
        if (openssl.EVP_EncryptUpdate(self.encryption, dst.ptr, &out_len, src.ptr, len) != 0)
            return error.EncryptionError;
    }

    pub fn decrypt(self: *CFB8Cipher, dst: []u8, src: []const u8) !void {
        var len: c_int = @intCast(src.len);
        var out_len = len;
        if (openssl.EVP_DecryptUpdate(self.decryption, dst.ptr, &out_len, src.ptr, len) != 0)
            return error.EncryptionError;
    }

    test "init" {
        const key: [16]u8 = undefined;
        const cipher = try CFB8Cipher.init(key);
        _ = cipher;
    }
};

pub const RSAKeyPair = struct {
    const KEY_LENGTH = 1024;

    rsa: *openssl.RSA,
    public: [162]u8,
    mojang_ctx: *openssl.SSL_CTX,

    pub fn generate() !RSAKeyPair {
        var return_int: c_int = 0;
        var rsa = openssl.RSA_new().?;
        var bn = openssl.BN_new().?;
        defer openssl.BN_free(bn);

        return_int = openssl.BN_set_word(bn, openssl.RSA_F4);
        std.debug.assert(return_int == 1);

        // Generating key
        std.log.debug("Generating key...", .{});
        return_int = openssl.RSA_generate_key_ex(rsa, KEY_LENGTH, bn, null);
        std.debug.assert(return_int == 1);

        // Writing to buffer using ASN1 DER format
        var bio = openssl.BIO_new(openssl.BIO_s_secmem()).?;
        defer _ = openssl.BIO_free(bio);
        return_int = openssl.i2d_RSA_PUBKEY_bio(bio, rsa);
        std.debug.assert(return_int == 1);

        // Copying from BIO to array
        var pending = openssl.BIO_pending(bio);
        std.debug.assert(pending == 162);
        var public: [162]u8 = undefined;
        return_int = openssl.BIO_read(bio, &public, pending);

        return RSAKeyPair{
            .rsa = rsa,
            .public = public,
            .mojang_ctx = undefined,
        };
    }

    pub fn decrypt(self: *RSAKeyPair, dst: []u8, src: []const u8) !usize {
        return @intCast(openssl.RSA_private_decrypt(@intCast(src.len), src.ptr, dst.ptr, self.rsa, openssl.RSA_PKCS1_PADDING));
    }
};

pub fn hexdigest(hash_in: [20]u8) ![]u8 {
    var hash = hash_in;
    var is_signed = false;
    // If signed, unsign and keep track that the hash was signed
    if ((hash[0] & 0x80) != 0) {
        is_signed = true;
        for (0..20) |i| {
            hash[i] = ~hash[i];
        }
        hash[19] += 1;
    }

    var hex_hash: [42]u8 = undefined;
    for (hash, 0..) |h, i| {
        _ = try std.fmt.bufPrint(hex_hash[1 + (i * 2) ..], "{x:0>2}", .{h});
    }
    if (is_signed) hex_hash[0] = '-';

    return hex_hash[@intFromBool(!is_signed)..41];
}

test "CFB8Cipher" {
    std.testing.refAllDecls(CFB8Cipher);
    std.testing.refAllDecls(RSAKeyPair);
}

test "hexdigest" {
    var text = [_]u8{ 'N', 'o', 't', 'c', 'h' };
    var expected = [_]u8{
        '4', 'e', 'd', '1', 'f', '4', '6', 'b', 'b', 'e',
        '0', '4', 'b', 'c', '7', '5', '6', 'b', 'c', 'b',
        '1', '7', 'c', '0', 'c', '7', 'c', 'e', '3', 'e',
        '4', '6', '3', '2', 'f', '0', '6', 'a', '4', '8',
    };
    var hash: [20]u8 = undefined;
    var context: openssl.SHA_CTX = undefined;

    _ = openssl.SHA1_Init(&context);
    _ = openssl.SHA1_Update(&context, &text, text.len);
    _ = openssl.SHA1_Final(&hash, &context);

    var hex = try hexdigest(hash);

    try std.testing.expectEqualSlices(u8, &expected, hex);
}
