package com.example.keyencryptlib;

import android.content.Context;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import java.util.concurrent.Executor;

/**
 * 封装生物识别认证的工具类
 */
public class BiometricHelper {

    public interface BiometricCallback {
        void onAuthenticationSucceeded();
        void onAuthenticationFailed(String errorMessage);
    }

    /**
     * 使用 BiometricPrompt 进行生物识别认证
     *
     * @param context  应用上下文（必须为 FragmentActivity 类型）
     * @param callback 认证结果回调
     */
    public static void authenticate(@NonNull Context context, @NonNull BiometricCallback callback) {
        BiometricManager biometricManager = BiometricManager.from(context);
        if (biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS) {
            Executor executor = ContextCompat.getMainExecutor(context);
            BiometricPrompt biometricPrompt = new BiometricPrompt((androidx.fragment.app.FragmentActivity) context, executor,
                    new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            callback.onAuthenticationSucceeded();
                        }
                        @Override
                        public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                            callback.onAuthenticationFailed(errString.toString());
                        }
                        @Override
                        public void onAuthenticationFailed() {
                            callback.onAuthenticationFailed("Authentication failed");
                        }
                    });
            BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                    .setTitle("生物识别认证")
                    .setSubtitle("请进行生物识别认证以使用加解密功能")
                    .setNegativeButtonText("取消")
                    .build();
            biometricPrompt.authenticate(promptInfo);
        } else {
            callback.onAuthenticationFailed("生物识别不可用");
        }
    }
}
