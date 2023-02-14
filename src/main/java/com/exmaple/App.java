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
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.json.JSONObject;

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
    String jsonStr = getJsonStr();
    byte[] encrypted = encrypt(jsonStr, privateKey);
    System.out.println("encryptedText:");
    System.out.println(decodeHex(encrypted));

    // 複合化
    String decryptText = decrypt(encrypted, publicKey);
    System.out.println("decryptText:");
    System.out.println(decryptText);

  }

  /**
   * JSON文字列を取得
   */
  private static String getJsonStr() {
    JSONObject json = new JSONObject();
    json.put("issuredDate", new Date());
    json.put("product", "REPORT");
    return json.toString();
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
   * byte配列を16進数表記に変換
   */
  private static String decodeHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
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
