import 'dart:convert';

import 'package:ad_hoc_ident/ad_hoc_ident.dart';
import 'package:crypto/crypto.dart' as c;

/// Uses the crypto package to encrypt an existing [AdHocIdentity].
class CryptoAdHocIdentityEncrypter implements AdHocIdentityEncrypter {
  /// Uses the MD5 algorithm to encrypt an existing [AdHocIdentity].
  static final md5 = CryptoAdHocIdentityEncrypter(c.md5.convert);

  /// Uses the SHA-1 algorithm to encrypt an existing [AdHocIdentity].
  static final sha1 = CryptoAdHocIdentityEncrypter(c.sha1.convert);

  /// Uses the SHA-224 algorithm to encrypt an existing [AdHocIdentity].
  static final sha224 = CryptoAdHocIdentityEncrypter(c.sha224.convert);

  /// Uses the SHA-256 algorithm to encrypt an existing [AdHocIdentity].
  static final sha256 = CryptoAdHocIdentityEncrypter(c.sha256.convert);

  /// Uses the SHA-384 algorithm to encrypt an existing [AdHocIdentity].
  static final sha384 = CryptoAdHocIdentityEncrypter(c.sha384.convert);

  /// Uses the SHA-512 algorithm to encrypt an existing [AdHocIdentity].
  static final sha512 = CryptoAdHocIdentityEncrypter(c.sha512.convert);

  /// Uses the SHA-512/224 algorithm to encrypt an existing [AdHocIdentity].
  static final sha512_224 = CryptoAdHocIdentityEncrypter(c.sha512224.convert);

  /// Uses the SHA-512/256 algorithm to encrypt an existing [AdHocIdentity].
  static final sha512_256 = CryptoAdHocIdentityEncrypter(c.sha512256.convert);

  /// The encryption algorithm to use.
  final c.Digest Function(List<int> inputBytes) delegate;

  /// Creates an [CryptoAdHocIdentityEncrypter] that uses
  /// the [delegate] encryption algorithm.
  ///
  /// The [delegate] function is applied to the [AdHocIdentity.identifier].
  /// The [AdHocIdentity.type] remains unchanged.
  const CryptoAdHocIdentityEncrypter(this.delegate);

  @override
  AdHocIdentity encrypt(AdHocIdentity identity) {
    final utfBytes = utf8.encode(identity.identifier);
    final hashBytes = delegate(utfBytes).bytes;
    final hexIdentity = base64.encode(hashBytes);
    final result = AdHocIdentity(type: identity.type, identifier: hexIdentity);
    return result;
  }
}
