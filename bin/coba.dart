import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

class Encryptions {
  static final String initVector = "19458wgurhvshh00";
  static final String keyEncrypt = "2020o08rg04hug404088ge4au3bax234";

  static String encrypt(String value) {
    try {
      final keyBytes = utf8.encode(keyEncrypt);
      final ivBytes = utf8.encode(initVector);
      final cipher = CBCBlockCipher(AESEngine())
        ..init(
            true,
            ParametersWithIV(KeyParameter(keyBytes as Uint8List),
                ivBytes as Uint8List)); // true for encryption

      final inputBytes = utf8.encode(value);
      final paddedInput = _pad(inputBytes as Uint8List, cipher.blockSize);
      final outputBytes = _processBlocks(cipher, paddedInput);

      return base64Encode(outputBytes);
    } catch (ex) {
      print(ex);
      return "";
    }
  }

  static String decrypt(String encrypted) {
    try {
      final keyBytes = utf8.encode(keyEncrypt);
      final ivBytes = utf8.encode(initVector);
      final encryptedBytes = base64.decode(encrypted);

      final cipher = CBCBlockCipher(AESEngine())
        ..init(
            false,
            ParametersWithIV(KeyParameter(keyBytes as Uint8List),
                ivBytes as Uint8List)); // false for decryption

      final paddedOutput = _processBlocks(cipher, encryptedBytes);
      final output = _unpad(paddedOutput);

      return utf8.decode(output);
    } catch (ex) {
      print(ex);
      return "";
    }
  }

  static Uint8List _pad(Uint8List src, int blockSize) {
    var pad = blockSize - (src.length % blockSize);
    var list = List<int>.filled(src.length + pad, pad);
    list.setRange(0, src.length, src);
    return Uint8List.fromList(list);
  }

  static Uint8List _unpad(Uint8List src) {
    var padLength = src.last;
    return Uint8List.fromList(src.sublist(0, src.length - padLength));
  }

  static Uint8List _processBlocks(BlockCipher cipher, Uint8List input) {
    final output = Uint8List(input.length);

    for (int offset = 0; offset < input.length; offset += cipher.blockSize) {
      cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }
}

void main() {
  String originalText = "Hello, World!";
  String encryptedText = Encryptions.encrypt(originalText);
  print("Original Text: $originalText");
  print("Encrypted Text: $encryptedText");

  String decryptedText = Encryptions.decrypt(encryptedText);
  print("Decrypted Text: $decryptedText");
}
