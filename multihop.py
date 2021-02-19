from umbral import pre, keys, signing, config
from umbral.kfrags import KFrag

config.set_default_curve()

# Generate Umbral keys for Alice.
alices_private_key = keys.UmbralPrivateKey.gen_key()
alices_public_key = alices_private_key.get_pubkey()

alices_signing_key = keys.UmbralPrivateKey.gen_key()
alices_verifying_key = alices_signing_key.get_pubkey()
alices_signer = signing.Signer(private_key=alices_signing_key)

params = alices_private_key.params
plaintext = b'Proxy Re-Encryption is cool!'
ciphertext, capsule = pre.encrypt(alices_public_key, plaintext)

# Generate Umbral keys for Bob.
bobs_private_key = keys.UmbralPrivateKey.gen_key()
bobs_public_key = bobs_private_key.get_pubkey()

bobs_signing_key = keys.UmbralPrivateKey.gen_key()
bobs_verifying_key = bobs_signing_key.get_pubkey()
bobs_signer = signing.Signer(private_key=bobs_signing_key)

# Generate Umbral keys for Charlie.
charlies_private_key = keys.UmbralPrivateKey.gen_key()
charlies_public_key = charlies_private_key.get_pubkey()

charlies_signing_key = keys.UmbralPrivateKey.gen_key()
charlies_verifying_key = charlies_signing_key.get_pubkey()
charlies_signer = signing.Signer(private_key=charlies_signing_key)



kfrags_12 = pre.generate_kfrags(delegating_privkey=alices_private_key,
                             signer=alices_signer,
                             receiving_pubkey=bobs_public_key,
                             threshold=1,
                             N=1)

capsule.set_correctness_keys(delegating=alices_public_key,
                             receiving=bobs_public_key,
                             verifying=alices_verifying_key)

cfrags = list()           # Bob's cfrag collection
for kfrag in kfrags_12:
  cfrag = pre.reencrypt(kfrag=kfrag, capsule=capsule)
  cfrags.append(cfrag)    # Bob collects a cfrag

kfrags_23 = pre.generate_kfrags(delegating_privkey=bobs_private_key,
                             signer=bobs_signer,
                             receiving_pubkey=charlies_public_key,
                             threshold=1,
                             N=1)

capsule.clear_correctness_keys()

capsule.set_correctness_keys(delegating=bobs_public_key,
                             receiving=charlies_public_key,
                             verifying=bobs_verifying_key)

capsule.set_originating_key(originating=alices_public_key)

cfrags_23 = list()
# for kfrag, cfrag in zip(kfrags_23, cfrags):
#     cfrag_23 = pre.hop_reencrypt(kfrag, cfrag, capsule)
#     cfrags_23.append(cfrag_23)

for kfrag_12, kfrag_23 in zip(kfrags_12, kfrags_23):
    kfrag_23.bn_key = kfrag_12.bn_key*kfrag_23.bn_key
    kfrag_23.point_commitment = kfrag_23.bn_key*params.u
    cfrag_23 = pre.reencrypt(kfrag=kfrag_23, capsule=capsule, verify_kfrag=False)
    cfrags_23.append(cfrag_23)

for cfrag in cfrags_23:
  capsule.attach_cfrag(cfrag)

charlie_cleartext = pre.decrypt(ciphertext=ciphertext,
                            capsule=capsule,
                            decrypting_key=charlies_private_key)



pass