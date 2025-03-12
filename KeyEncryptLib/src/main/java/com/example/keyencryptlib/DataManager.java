package com.example.keyencryptlib;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class DataManager {
    // 模拟存储映射关系，实际项目可使用数据库持久化
    private static Map<String, byte[]> encryptedDataMap = new HashMap<>();

    /**
     * 存储加密后的数据，并生成一个唯一标识符返回给调用端。
     * 这里采用随机生成 UUID 的方式作为标识符，也可以使用数据哈希值等方式。
     *
     * @param encryptedData 加密后的数据字节数组
     * @return 唯一标识符，用于查询该加密数据
     */
    public static String storeEncryptedData(byte[] encryptedData) {
        // 生成唯一标识符（例如 UUID）
        String id = UUID.randomUUID().toString();
        encryptedDataMap.put(id, encryptedData);
        return id;
    }

    /**
     * 根据标识符查询出加密后的数据
     *
     * @param id 唯一标识符
     * @return 加密后的数据字节数组，如果未找到则返回 null
     */
    public static byte[] getEncryptedData(String id) {
        return encryptedDataMap.get(id);
    }

    /**
     * 可选：基于哈希值生成标识符（例如 SHA-256），如果需要数据唯一性检测
     */
    public static String generateIdFromData(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            // 转换为16进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if(hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            // 生成失败时返回随机 UUID
            return UUID.randomUUID().toString();
        }
    }
}

