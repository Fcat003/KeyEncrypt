package com.example.keyencrypt;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import java.security.KeyStore;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

public class RSATestActivity extends AppCompatActivity {

    private static final String TAG = "RSATestActivity";
    private static final String RSA_KEY_ALIAS = "RSA_Test";
    private static final int RSA_KEY_SIZE = 2048;
    // 使用 RSA/ECB/PKCS1Padding 模式
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // 使用一个简单布局
        setContentView(android.R.layout.simple_list_item_1);

        // 先进行生物识别认证
        BiometricManager biometricManager = BiometricManager.from(this);
        if (biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
            BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("生物识别认证")
                    .setSubtitle("请进行生物识别认证以执行 RSA 测试")
                    .setNegativeButtonText("取消")
                    .build();
            BiometricPrompt biometricPrompt = new BiometricPrompt(this,
                    ContextCompat.getMainExecutor(this), new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    // 认证成功后执行 RSA 测试
                    runRSATest();
                }
                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    Toast.makeText(RSATestActivity.this, "认证错误: " + errString, Toast.LENGTH_LONG).show();
                }
                @Override
                public void onAuthenticationFailed() {
                    Toast.makeText(RSATestActivity.this, "认证失败", Toast.LENGTH_LONG).show();
                }
            });
            biometricPrompt.authenticate(promptInfo);
        } else {
            Toast.makeText(this, "生物识别不可用", Toast.LENGTH_LONG).show();
        }
    }

    private void runRSATest() {
        try {
            generateRSAKeyPair();
            String plainText = "Hello RSA!";
            byte[] encryptedData = encryptData(plainText);
            String encryptedBase64 = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            Log.i(TAG, "Encrypted: " + encryptedBase64);
            byte[] decryptedData = decryptData(encryptedData);
            String decryptedText = new String(decryptedData, "UTF-8");
            Log.i(TAG, "Decrypted: " + decryptedText);
            Toast.makeText(this, "Decrypted: " + decryptedText, Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Log.e(TAG, "RSA test failed", e);
            Toast.makeText(this, "RSA test failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    /**
     * 生成 RSA 密钥对并存储到 Android Keystore 中
     */
    private void generateRSAKeyPair() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(RSA_KEY_ALIAS)) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    RSA_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(RSA_KEY_SIZE)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .build();
            keyPairGenerator.initialize(spec);
            keyPairGenerator.generateKeyPair();
            Log.i(TAG, "RSA key pair generated.");
        } else {
            Log.i(TAG, "RSA key pair already exists.");
        }
    }

    /**
     * 使用 Android Keystore 中的 RSA 公钥对数据加密
     */
    private byte[] encryptData(String plainText) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(RSA_KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new Exception("RSA key not found");
        }
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, ((KeyStore.PrivateKeyEntry) entry).getCertificate().getPublicKey());
        return cipher.doFinal(plainText.getBytes("UTF-8"));
    }

    /**
     * 使用 Android Keystore 中的 RSA 私钥对数据解密
     */
    private byte[] decryptData(byte[] cipherText) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(RSA_KEY_ALIAS, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new Exception("RSA key not found");
        }
        Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, ((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        return cipher.doFinal(cipherText);
    }
}
