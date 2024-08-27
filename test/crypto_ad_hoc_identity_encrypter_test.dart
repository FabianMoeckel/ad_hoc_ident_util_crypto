import 'package:ad_hoc_ident/ad_hoc_ident.dart';
import 'package:ad_hoc_ident_util_crypto/ad_hoc_ident_util_crypto.dart';
import 'package:test/test.dart';

class _TestConfig {
  final String inputIdentifier;
  final String expectedResultIdentifier;
  final CryptoAdHocIdentityEncrypter sut;
  final String algorithmName;

  _TestConfig(
      {required this.inputIdentifier,
      required this.expectedResultIdentifier,
      required this.sut,
      required this.algorithmName});
}

void _test(_TestConfig config) {
  final testIdentity =
      AdHocIdentity(type: 'test', identifier: config.inputIdentifier);
  final encryptedIdentity = config.sut.encrypt(testIdentity);
  expect(encryptedIdentity, isNotNull);
  expect(encryptedIdentity.identifier, equals(config.expectedResultIdentifier));
  expect(encryptedIdentity.type, equals(testIdentity.type));
}

void main() {
  group('successfully encrypts identifier with predefined implementations', () {
    const defaultInput = 'some private data';
    final testSet = {
      _TestConfig(
          algorithmName: 'md5',
          sut: CryptoAdHocIdentityEncrypter.md5,
          inputIdentifier: defaultInput,
          expectedResultIdentifier: 'cquPNT86M55o1HNACgvH6A=='),
      _TestConfig(
          algorithmName: 'sha1',
          sut: CryptoAdHocIdentityEncrypter.sha1,
          inputIdentifier: defaultInput,
          expectedResultIdentifier: '3+yLfzqGo2uZLNPiO4nD2yt4V8w='),
      _TestConfig(
          algorithmName: 'sha224',
          sut: CryptoAdHocIdentityEncrypter.sha224,
          inputIdentifier: defaultInput,
          expectedResultIdentifier: '1dLP7ZhyYiydgnOdObFp1UTIHapkgBx6Ay9v1w=='),
      _TestConfig(
          algorithmName: 'sha256',
          sut: CryptoAdHocIdentityEncrypter.sha256,
          inputIdentifier: defaultInput,
          expectedResultIdentifier:
              'yb5wgDAWKLr4LM4N0AgorRsnqU0o5RmZ9o1ZFMfPrn0='),
      _TestConfig(
          algorithmName: 'sha384',
          sut: CryptoAdHocIdentityEncrypter.sha384,
          inputIdentifier: defaultInput,
          expectedResultIdentifier:
              'XBn6w6f0RHcPnBcVdoRTSPC3XRS9q7tNKxQjRgRXrbJjjyvSntVVKWzxKNvvRmtt'),
      _TestConfig(
          algorithmName: 'sha512',
          sut: CryptoAdHocIdentityEncrypter.sha512,
          inputIdentifier: defaultInput,
          expectedResultIdentifier: 'vwaNvVCG4IUIDhisa1zrIKAHW3sdF97//8s0crZrqP'
              'BjHnPRNrONiyZDNjHWg7gH2aorJsWcgMRBVC2lXtS7OQ=='),
      _TestConfig(
          algorithmName: 'sha512_224',
          sut: CryptoAdHocIdentityEncrypter.sha512_224,
          inputIdentifier: defaultInput,
          expectedResultIdentifier: 'nUA/GgWUaprvo/nBKywXJpBrZenA0p8shKVJoQ=='),
      _TestConfig(
          algorithmName: 'sha512_256',
          sut: CryptoAdHocIdentityEncrypter.sha512_256,
          inputIdentifier: defaultInput,
          expectedResultIdentifier:
              '6FYJjsvZ5/7ZYlrb3+CgfFXdhWiGgpci+/SolVEwo7k='),
    };

    for (var config in testSet) {
      test(
        'successfully encrypts identifier with ${config.algorithmName}.',
        () => _test(config),
      );
    }
  });
}
