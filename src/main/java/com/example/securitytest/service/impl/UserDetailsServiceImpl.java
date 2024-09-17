package com.example.securitytest.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.securitytest.domain.LoginUser;
import com.example.securitytest.domain.User;
import com.example.securitytest.mapper.MenuMapper;
import com.example.securitytest.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    UserMapper userMapper;
    @Autowired
    MenuMapper menuMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        // 根据用户名查询用户信息
        LambdaQueryWrapper wrapper = new LambdaQueryWrapper<User>().eq(User::getUserName, username);
        User user = userMapper.selectOne(wrapper);
        System.out.println(user);
        //如果没有该用户就抛出异常
        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名或密码错误");
        }

        //TODO: 查询权限信息封装到LoginUser中
//        ArrayList<String> list = new ArrayList<>();
//        list.add("user");
        List<String> list = menuMapper.selectPermsByUserId(user.getId());
        System.out.println(list.toString());


        // 将用户信息封装到UserDetails实现类中
        return new LoginUser(user,list);
    }
}
