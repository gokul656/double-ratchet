bob
  * signed pre-key
  * identity key
  * one-time pre-key

alice
  * identity key
  * ephemeral key ( temp key )


perform exchange
  * calculte D1, D2, D3, D4 using pub keys
  * dh1 = signed.exchage(a.ikey)
  * dh2 = identity.exchange(a.eph)
  * dh3 = signed.exchange(a.eph)
  * dh4 = onetime.exchange(a.eph)

  * secret key = KDF(D1 + D2 + D3 + D4)

```
assert sk 1 == sk 2
```


> Ref: https://nfil.dev/coding/encryption/python/double-ratchet-example/