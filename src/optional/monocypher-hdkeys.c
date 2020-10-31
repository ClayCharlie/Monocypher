//this implements a small modification: the chain code for an xpriv (kR,kL) is F_mono(kR).  The reason for this is so that an xpriv can be only 64 bytes.

#include "../monocypher.h"
#define COPY(dst, src, size)       FOR(i, 0, size) (dst)[i] = (src)[i]


static chain_code_xpriv(uint8_t chain[32],const uint8_t xpriv[64])
{
    static const uint8_t salt[] = {'m','o','n','o'};
    crypto_blake2b_general(chain,32,salt,4,xpriv+32,32);
}

static void passthrough_hash512(uint8_t hash[64],const uint8_t* msg, size_t message_size)
{
    COPY(hash,msg,64);
}

extern const crypto_sign_vtable crypto_blake2b_vtable;

//this implementation tries to implement signing without exposing any symbols from monocypher.     To accomplish this it's a bit of a hack where the vtable is a passthrough such that hash() in the prefix
//copies the xpriv to directly to the output as recommended in the bip32-ed25519 spec.  Then the rest of the signing is still crypto_blake2b_general
//this depends on the current implementation which uses the simple ctx->hash->hash() api for the first pass and the other functions for the subsequent passes.

static const crypto_sign_vtable passthrough_hash_vtable={
    passthrough_hash512,
    crypto_blake2b_vtable->init,
    crypto_blake2b_vtable->update,
    crypto_blake2b_vtable->final,
    crypto_blake2b_vtable->ctx_size
};

void crypto_xkey_public_key(uint8_t xpub[64],const uint8_t xpriv[64])
{
    chain_code_xpriv(xpub+32,xpriv);
    crypto_sign_public_key_custom_hash(xpub,xpriv,&passthrough_hash_vtable);
}

void crypto_xkey_sign(uint8_t xpriv[64],const uint8_t* msg,size_t msg_len)
{
    crypto_sign_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract*)&ctx;
    uint8_t A[32];
    crypto_sign_public_key_custom_hash(A,xpriv,&passthrough_hash_vtable);
    
    crypto_sign_init_first_pass_custom_hash(actx,xpriv,A,&passthrough_hash_vtable);
    crypto_sign_update          (actx, message, message_size);
    crypto_sign_init_second_pass(actx);
    crypto_sign_update          (actx, message, message_size);
    crypto_sign_final           (actx, signature);
}


void crypto_xkey_descend_priv(uint8_t child_xpriv[64],const uint8_t parent_xkey[64],uint8_t index_digest[32],uint8_t is_hardened)
{
    
}
