package com.example.keyencryptlib;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.example.keyencryptlib.AlgorithmType;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 可信操作模块
 *
 * 该模块封装了在 TEE（通过 Android Keystore）中执行密钥生成、加密和解密操作的核心功能，
 * 并采用传参方式配置，便于后续扩展。
 *
 * 支持：
 * - AES/GCM/NoPadding：用于对任意字符串加密，返回组合了 IV 的密文（IV 固定 12 字节）。
 * - RSA：采用 "RSA/ECB/PKCS1Padding" 对少量数据进行加解密（仅适用于小数据）。
 */
public class TrustedOperationManager {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private KeyStore keyStore;

    public TrustedOperationManager() throws Exception {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
    }

    // ----- AES 部分 -----

    /**
     * 生成 AES 密钥，并存储在 Keystore 中。
     *
     * @param keyAlias          密钥别名
     * @param keySize           密钥位数（128 或 256）
     * @param blockMode         块模式，例如 "GCM"
     * @param padding           填充方式，例如 "NoPadding"（GCM模式通常不使用填充）
     * @param userAuthRequired  是否需要生物认证
     * @throws Exception
     */
    public void generateAESKey(String keyAlias, int keySize, String blockMode, String padding, boolean userAuthRequired) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(keySize)
                .setBlockModes(blockMode)
                .setEncryptionPaddings(padding)
                .setUserAuthenticationRequired(userAuthRequired)
                .build();
        keyGenerator.init(spec);
        keyGenerator.generateKey();
    }

    /**
     * 从 Keystore 获取 AES 密钥
     */
    public SecretKey getAESKey(String keyAlias) throws Exception {
        KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) keyStore.getEntry(keyAlias, null);
        return entry.getSecretKey();
    }

    /**
     * 使用 AES/GCM/NoPadding 加密数据。系统自动生成 IV（12字节），返回组合数据：IV || 密文。
     */
    public byte[] encryptDataAES(String keyAlias, String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey key = getAESKey(keyAlias);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] iv = cipher.getIV();
        byte[] ciphertext = cipher.doFinal(plainText.getBytes("UTF-8"));
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return combined;
    }

    /**
     * 使用 AES/GCM/NoPadding 解密数据。输入数据前 12 字节为 IV。
     */
    public String decryptDataAES(String keyAlias, byte[] combined) throws Exception {
        int ivLength = 12;
        if (combined.length < ivLength) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }
        byte[] iv = new byte[ivLength];
        System.arraycopy(combined, 0, iv, 0, ivLength);
        int ciphertextLength = combined.length - ivLength;
        byte[] ciphertext = new byte[ciphertextLength];
        System.arraycopy(combined, ivLength, ciphertext, 0, ciphertextLength);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey key = getAESKey(keyAlias);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, "UTF-8");
    }

    // ----- RSA 部分 -----

    /**
     * 生成 RSA 密钥对，并存储在 Keystore 中。
     */
    public void generateRSAKeyPair(String keyAlias, int keySize, String transformation) throws Exception {
        if (keyStore.containsAlias(keyAlias)) {
            return;
        }
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(keySize);
        // 根据 transformation 选择填充模式
        if (transformation.contains("OAEP")) {
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
        } else {
            builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
        }
        builder.setUserAuthenticationRequired(false);
        keyPairGenerator.initialize(builder.build());
        keyPairGenerator.generateKeyPair();
    }

    /**
     * 使用 RSA 加密数据。只适用于小数据加密。
     */
    public byte[] encryptDataRSA(String keyAlias, String transformation, byte[] data) throws Exception {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalArgumentException("RSA key not found");
        }
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey());
        return cipher.doFinal(data);
    }

    /**
     * 使用 RSA 解密数据。
     */
    public byte[] decryptDataRSA(String keyAlias, String transformation, byte[] cipherText) throws Exception {
        KeyStore.Entry entry = keyStore.getEntry(keyAlias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalArgumentException("RSA key not found");
        }
        PrivateKey privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherText);
    }

    // ----- 统一接口 -----

    /**
     * 根据传入的 AlgorithmType 对明文进行加密。
     * 对于 AES_GCM_128 / AES_GCM_256，返回组合数据：IV || 密文；
     * 对于 RSA_2048 / RSA_3072 / RSA_4096，直接返回加密数据。
     */
    public byte[] encryptData(AlgorithmType algorithmType, String plainText) throws Exception {
        switch (algorithmType) {
            case AES_GCM_128:
                if (!keyStore.containsAlias("AES_GCM_128")) {
                    generateAESKey("AES_GCM_128", 128, KeyProperties.BLOCK_MODE_GCM, KeyProperties.ENCRYPTION_PADDING_NONE, false);
                }
                return encryptDataAES("AES_GCM_128", plainText);
            case AES_GCM_256:
                if (!keyStore.containsAlias("AES_GCM_256")) {
                    generateAESKey("AES_GCM_256", 256, KeyProperties.BLOCK_MODE_GCM, KeyProperties.ENCRYPTION_PADDING_NONE, false);
                }
                return encryptDataAES("AES_GCM_256", plainText);
            case RSA_2048:
                if (!keyStore.containsAlias("RSA_2048")) {
                    generateRSAKeyPair("RSA_2048", 2048, "RSA/ECB/PKCS1Padding");
                }
                return encryptDataRSA("RSA_2048", "RSA/ECB/PKCS1Padding", plainText.getBytes("UTF-8"));
            case RSA_3072:
                if (!keyStore.containsAlias("RSA_3072")) {
                    generateRSAKeyPair("RSA_3072", 3072, "RSA/ECB/PKCS1Padding");
                }
                return encryptDataRSA("RSA_3072", "RSA/ECB/PKCS1Padding", plainText.getBytes("UTF-8"));
            case RSA_4096:
                if (!keyStore.containsAlias("RSA_4096")) {
                    generateRSAKeyPair("RSA_4096", 4096, "RSA/ECB/PKCS1Padding");
                }
                return encryptDataRSA("RSA_4096", "RSA/ECB/PKCS1Padding", plainText.getBytes("UTF-8"));
            default:
                throw new IllegalArgumentException("Unsupported algorithm type");
        }
    }

    /**
     * 根据传入的 AlgorithmType 对加密数据进行解密，返回明文。
     * 对于 AES，加密数据为 IV || 密文；对于 RSA，则直接解密。
     */
    public String decryptData(AlgorithmType algorithmType, byte[] cipherData) throws Exception {
        switch (algorithmType) {
            case AES_GCM_128:
                return decryptDataAES("AES_GCM_128", cipherData);
            case AES_GCM_256:
                return decryptDataAES("AES_GCM_256", cipherData);
            case RSA_2048:
                byte[] dec2048 = decryptDataRSA("RSA_2048", "RSA/ECB/PKCS1Padding", cipherData);
                return new String(dec2048, "UTF-8");
            case RSA_3072:
                byte[] dec3072 = decryptDataRSA("RSA_3072", "RSA/ECB/PKCS1Padding", cipherData);
                return new String(dec3072, "UTF-8");
            case RSA_4096:
                byte[] dec4096 = decryptDataRSA("RSA_4096", "RSA/ECB/PKCS1Padding", cipherData);
                return new String(dec4096, "UTF-8");
            default:
                throw new IllegalArgumentException("Unsupported algorithm type");
        }
    }

}
