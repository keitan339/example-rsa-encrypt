package com.exmaple;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class App {

  private static final String ALGORITHM = "RSA";
  private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

  public static void main(String[] args) throws Exception {

    // 鍵仕様の指定
    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);

    // 秘密鍵の取得
    KeySpec privateKeySpec = new PKCS8EncodedKeySpec(getPrivateKey());
    PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

    // 公開鍵の取得
    KeySpec publicKeySpec = new X509EncodedKeySpec(getPublicKey());
    PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

    // 暗号化
    String plainText = getPlainText();
    byte[] encrypted = encrypt(plainText, privateKey);
    String encryptedText = encodeBase64(encrypted);
    System.out.println("encryptedText:");
    System.out.println(encryptedText);

    // 複合化
    String decryptText = decrypt(decodeBase64(encryptedText), publicKey);
    System.out.println("decryptText:");
    System.out.println(decryptText);

  }

  /**
   * 平文を取得
   */
  private static String getPlainText() {
    String plainText = new SimpleDateFormat("yyMMddHHmmssSSS").format(new Date()) + "," + "1000";
    return plainText;
  }

  /**
   * 秘密鍵データを取得
   */
  private static byte[] getPrivateKey() throws IOException, URISyntaxException {
    URL url = App.class.getResource("/private.der");
    return Files.readAllBytes(Paths.get(url.toURI()));
  }

  /**
   * 公開鍵データを取得
   */
  private static byte[] getPublicKey() throws IOException, URISyntaxException {
    URL url = App.class.getResource("/public.der");
    return Files.readAllBytes(Paths.get(url.toURI()));
  }

  /**
   * byte配列をBase64エンコード
   */
  private static String encodeBase64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  /**
   * byte配列をBase64エンコード
   */
  private static byte[] decodeBase64(String base64str) {
    return Base64.getDecoder().decode(base64str);
  }

  /**
   * 秘密鍵で暗号
   */
  private static byte[] encrypt(String plainText, PrivateKey privateKey) throws NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, privateKey);
    return cipher.doFinal(plainText.getBytes());
  }

  /**
   * 公開鍵で複合化
   */
  private static String decrypt(byte[] encrypted, PublicKey publicKey) throws NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, publicKey);
    byte[] decrypted = cipher.doFinal(encrypted);
    return new String(decrypted);

  }
}
