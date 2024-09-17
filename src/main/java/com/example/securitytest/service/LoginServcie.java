package com.example.securitytest.service;

import com.example.securitytest.domain.ResponseResult;
import com.example.securitytest.domain.User;

public interface LoginServcie {
    ResponseResult login(User user);

    ResponseResult logout();

    ResponseResult addUser(User user);
}
