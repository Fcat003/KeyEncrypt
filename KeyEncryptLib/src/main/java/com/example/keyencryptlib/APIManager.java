package com.example.keyencryptlib;

import android.content.Context;
import androidx.annotation.NonNull;
import com.example.keyencryptlib.DataManager;
import com.example.keyencryptlib.TrustedOperationManager;

public class APIManager {

    private static APIManager instance;
    private TrustedOperationManager trustedOperationManager;

    private APIManager(Context context) throws Exception {
        trustedOperationManager = new TrustedOperationManager();
        // 此处无需提前生成密钥，统一在加解密时自动生成（若密钥不存在）
    }

    public static synchronized APIManager getInstance(Context context) throws Exception {
        if (instance == null) {
            instance = new APIManager(context);
        }
        return instance;
    }

    /**
     * 先进行生物识别认证，然后对传入明文按指定算法进行加密，
     * 并将加密数据存储，返回标识符。
     */
    public void authenticateAndEncrypt(@NonNull Context context, final String plainText, final AlgorithmType algorithmType, @NonNull final OperationCallback<String> callback) {
        BiometricHelper.authenticate(context, new BiometricHelper.BiometricCallback() {
            @Override
            public void onAuthenticationSucceeded() {
                try {
                    byte[] cipherData = trustedOperationManager.encryptData(algorithmType, plainText);
                    // 将加密数据存储到数据管理模块，生成唯一标识符返回
                    String id = DataManager.storeEncryptedData(cipherData);
                    callback.onSuccess(id);
                } catch (Exception e) {
                    callback.onFailure(e.getMessage());
                }
            }
            @Override
            public void onAuthenticationFailed(String errorMessage) {
                callback.onFailure(errorMessage);
            }
        });
    }

    /**
     * 先进行生物识别认证，然后根据标识符查询加密数据，
     * 按指定算法进行解密，返回明文。
     */
    public void authenticateAndDecrypt(@NonNull Context context, final String id, final AlgorithmType algorithmType, @NonNull final OperationCallback<String> callback) {
        BiometricHelper.authenticate(context, new BiometricHelper.BiometricCallback() {
            @Override
            public void onAuthenticationSucceeded() {
                try {
                    byte[] cipherData = DataManager.getEncryptedData(id);
                    if (cipherData == null) {
                        callback.onFailure("未找到对应的加密数据");
                        return;
                    }
                    String plainText = trustedOperationManager.decryptData(algorithmType, cipherData);
                    callback.onSuccess(plainText);
                } catch (Exception e) {
                    callback.onFailure(e.getMessage());
                }
            }
            @Override
            public void onAuthenticationFailed(String errorMessage) {
                callback.onFailure(errorMessage);
            }
        });
    }
}
