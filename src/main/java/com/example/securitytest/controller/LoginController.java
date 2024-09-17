package com.example.securitytest.controller;

import com.example.securitytest.domain.ResponseResult;
import com.example.securitytest.domain.User;
import com.example.securitytest.service.LoginServcie;
import org.apiguardian.api.API;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class LoginController {
    @Autowired
    private LoginServcie loginServcie;
    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user){
        System.out.println("开始登录");
        return loginServcie.login(user);
    }
    @PostMapping("/user/logout")
    public ResponseResult logout(){
        System.out.println("开始登出");
        return loginServcie.logout();
    }
    //增加用户
    @PostMapping("/user/add")
    public ResponseResult addUser(@RequestBody User user){
        System.out.println("开始增加用户");
        return loginServcie.addUser(user);
    }
}