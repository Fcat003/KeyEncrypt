package com.example.keyencrypt;

import android.content.Intent;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.example.keyencryptlib.APIManager;
import com.example.keyencryptlib.AlgorithmType;
import com.example.keyencryptlib.OperationCallback;

import java.util.Locale;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";
    private EditText editTextInput;
    private Spinner spinnerAlgorithm;
    private TextView textViewOutput;
    // 存储加密后映射的唯一标识符
    private String encryptedId;
    private APIManager apiManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 绑定控件
        editTextInput = findViewById(R.id.editTextInput);
        spinnerAlgorithm = findViewById(R.id.spinnerAlgorithm);
        textViewOutput = findViewById(R.id.textViewOutput);

        // 设置下拉框数据，基于 AlgorithmType 枚举
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new String[] {
                        AlgorithmType.AES_GCM_128.name(),
                        AlgorithmType.AES_GCM_256.name(),
                        AlgorithmType.RSA_2048.name(),
                        AlgorithmType.RSA_3072.name(),
                        AlgorithmType.RSA_4096.name()
                });
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerAlgorithm.setAdapter(adapter);

        try {
            apiManager = APIManager.getInstance(this);
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "初始化 APIManager 失败: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }

        findViewById(R.id.buttonEncrypt).setOnClickListener(this::onEncryptClicked);
        findViewById(R.id.buttonDecrypt).setOnClickListener(this::onDecryptClicked);
        findViewById(R.id.button).setOnClickListener(v->{
            Intent intent = new Intent(this, RSATestActivity.class);
            this.startActivity(intent);
        });
    }

    /**
     * 点击“加密”按钮：获取输入内容及选中的算法类型，
     * 调用 APIManager 进行生物识别认证后加密，返回唯一标识符。
     */
    public void onEncryptClicked(View view) {
        final String input = editTextInput.getText().toString().trim();
        if (input.isEmpty()) {
            Toast.makeText(this, "请输入待加密内容", Toast.LENGTH_SHORT).show();
            return;
        }
        // 获取下拉框选中的算法
        String selected = spinnerAlgorithm.getSelectedItem().toString();
        AlgorithmType algorithmType = AlgorithmType.valueOf(selected);
        apiManager.authenticateAndEncrypt(this, input, algorithmType, new OperationCallback<String>() {
            @Override
            public void onSuccess(String result) {
                encryptedId = result;
                runOnUiThread(() -> textViewOutput.setText(String.format(Locale.US, "加密结果:\n%s", result)));
            }
            @Override
            public void onFailure(String errorMessage) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "加密失败: " + errorMessage, Toast.LENGTH_LONG).show());
            }
        });
    }

    /**
     * 点击“解密”按钮：获取选中的算法类型，
     * 调用 APIManager 根据标识符查找加密数据，再进行生物识别认证后解密显示明文。
     */
    public void onDecryptClicked(View view) {
        if (encryptedId == null) {
            Toast.makeText(this, "请先进行加密操作", Toast.LENGTH_SHORT).show();
            return;
        }
        String selected = spinnerAlgorithm.getSelectedItem().toString();
        AlgorithmType algorithmType = AlgorithmType.valueOf(selected);
        apiManager.authenticateAndDecrypt(this, encryptedId, algorithmType, new OperationCallback<String>() {
            @Override
            public void onSuccess(String result) {
                runOnUiThread(() -> textViewOutput.setText(String.format(Locale.US, "解密结果:\n%s", result)));
            }
            @Override
            public void onFailure(String errorMessage) {
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "解密失败: " + errorMessage, Toast.LENGTH_LONG).show());
            }
        });
    }
}
