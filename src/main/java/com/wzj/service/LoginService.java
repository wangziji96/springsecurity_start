package com.wzj.service;

import com.wzj.domain.ResponseResult;
import com.wzj.domain.User;

/**
 * @Author wzj
 * @Date 2022/2/20 15:13
 */
public interface LoginService {
    ResponseResult login(User user);
    ResponseResult logout();
}
