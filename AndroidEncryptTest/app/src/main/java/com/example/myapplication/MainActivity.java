package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //testEncryptDecrypt();
        //testDecrpyt();

        String key = "123";
        String en = "VNZvUH5FDstjDBNlzFO+8w==";
        String de = "";
        try {
            de = decrypt(en,key);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        Log.d("TEST", "decrypted:$de");

    }

    private final String characterEncoding = "UTF-8";
    private final String cipherTransformation = "AES/CBC/PKCS5Padding";
    private final String aesEncryptionAlgorithm = "AES";

    public  byte[] decrypt(byte[] cipherText, byte[] key, byte [] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpecy = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpecy, ivParameterSpec);
        cipherText = cipher.doFinal(cipherText);
        return cipherText;
    }

    public byte[] encrypt(byte[] plainText, byte[] key, byte [] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
        Cipher cipher = Cipher.getInstance(cipherTransformation);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, aesEncryptionAlgorithm);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        plainText = cipher.doFinal(plainText);
        return plainText;
    }

    private byte[] getKeyBytes(String key) throws UnsupportedEncodingException {
        byte[] keyBytes= new byte[16];
        byte[] parameterKeyBytes= key.getBytes(characterEncoding);
        System.arraycopy(parameterKeyBytes, 0, keyBytes, 0, Math.min(parameterKeyBytes.length, keyBytes.length));
        return keyBytes;
    }

    /// <summary>
    /// Encrypts plaintext using AES 128bit key and a Chain Block Cipher and returns a base64 encoded string
    /// </summary>
    /// <param name="plainText">Plain text to encrypt</param>
    /// <param name="key">Secret key</param>
    /// <returns>Base64 encoded string</returns>
    public String encrypt(String plainText, String key) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        byte[] plainTextbytes = plainText.getBytes(characterEncoding);
        byte[] keyBytes = getKeyBytes(key);
        return Base64.encodeToString(encrypt(plainTextbytes,keyBytes, keyBytes), Base64.DEFAULT);
    }

    /// <summary>
    /// Decrypts a base64 encoded string using the given key (AES 128bit key and a Chain Block Cipher)
    /// </summary>
    /// <param name="encryptedText">Base64 Encoded String</param>
    /// <param name="key">Secret Key</param>
    /// <returns>Decrypted String</returns>
    public String decrypt(String encryptedText, String key) throws KeyException, GeneralSecurityException, GeneralSecurityException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] cipheredBytes = Base64.decode(encryptedText, Base64.DEFAULT);
        byte[] keyBytes = getKeyBytes(key);
        return new String(decrypt(cipheredBytes, keyBytes, keyBytes), characterEncoding);
    }

































    public void testEncryptDecrypt(){

        String password = "password";
        String message = "hello world";

        if (BuildConfig.DEBUG) {
            AESCrypt.DEBUG_LOG_ENABLED = true;
        }

        String encryptedMsg = null;
        try {
            encryptedMsg = AESCrypt.encrypt(password, message);
            Log.d("TEST", "encrypted:$encryptedMsg");
        }catch (GeneralSecurityException e){
            fail("error occurred during encrypt");
            e.printStackTrace();
        }

        String messageAfterDecrypt = null;
        try {
            messageAfterDecrypt = AESCrypt.decrypt(password, encryptedMsg);
            Log.d("TEST", "decrypted:$messageAfterDecrypt");

        }catch (GeneralSecurityException e){
            fail("error occurred during Decrypt");
            e.printStackTrace();
        }

        if (!messageAfterDecrypt.equals(message)){
            fail("messages don't match after encrypt and decrypt");
        }
    }

    public void testEncryt(){

        String password = "password";
        String message = "hello world";

        try {
            String encryptedMsg = AESCrypt.encrypt(password, message);
            Log.d("TEST", "encrypted:$encryptedMsg");
        }catch (GeneralSecurityException e){
            //handle error

            fail("error occurred during encrypt");
            e.printStackTrace();
        }
    }

    public void testDecrpyt(){
        String password = "password";
        String encryptedMsg = "2B22cS3UC5s35WBihLBo8w==";

        password = "123";
        encryptedMsg = "ytfhFOMhuH+xVMfIok0+Ww==";

        try {

            String messageAfterDecrypt = AESCrypt.decrypt2(password, encryptedMsg);
            Log.d("TEST", "encrypted:$messageAfterDecrypt");
        }catch (GeneralSecurityException e){
            fail("error occurred during Decrypt");
            e.printStackTrace();
        }
    }

    public void fail(String message){

    }

}
