const std = @import("std");

const crypto = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/aes.h");
});

const CipherError = error{
    CIPHER_INIT_ERROR,
    ENCRYPTION_INIT_ERROR,
    DECRYPTION_INIT_ERROR,
};

pub const Cipher = struct {
    key: [16]u8,
    block_size: usize,
    enc_ctx: *const crypto.EVP_CIPHER_CTX,
    dec_ctx: *const crypto.EVP_CIPHER_CTX,

    pub fn init(key: [16]u8) !Cipher {
        const c_key: [*]const u8 = key[0..].ptr;

        const enc_ctx: crypto.EVP_CIPHER_CTX = undefined;
        const dec_ctx: crypto.EVP_CIPHER_CTX = undefined;

        _ = crypto.EVP_CIPHER_CTX_init(@constCast(&enc_ctx));
        _ = crypto.EVP_EncryptInit_ex2(@constCast(&enc_ctx), crypto.EVP_aes_128_cfb8(), c_key, c_key, null);

        _ = crypto.EVP_CIPHER_CTX_init(@constCast(&dec_ctx));
        _ = crypto.EVP_DecryptInit_ex2(@constCast(&dec_ctx), crypto.EVP_aes_128_cfb8(), c_key, c_key, null);

        const block_size = crypto.EVP_CIPHER_block_size(crypto.EVP_aes_128_cfb8());

        return .{
            .key = key,
            .block_size = @intCast(block_size),
            .enc_ctx = &enc_ctx,
            .dec_ctx = &dec_ctx,
        };
    }

    pub fn deinit(self: *const Cipher) void {
        crypto.EVP_CIPHER_CTX_free(self.enc_ctx);
        crypto.EVP_CIPHER_CTX_free(self.dec_ctx);
    }
};

test Cipher {
    std.testing.refAllDecls(Cipher);
}
