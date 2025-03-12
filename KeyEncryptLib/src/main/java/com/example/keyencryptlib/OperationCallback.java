package com.example.keyencryptlib;

/**
 * 统一操作回调接口
 *
 * @param <T> 返回数据类型
 */
public interface OperationCallback<T> {
    void onSuccess(T result);
    void onFailure(String errorMessage);
}

