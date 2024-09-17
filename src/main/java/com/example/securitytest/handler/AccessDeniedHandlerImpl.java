package com.example.securitytest.handler;

import com.alibaba.fastjson.JSON;
import com.example.securitytest.domain.ResponseResult;
import com.example.securitytest.utils.WebUtils;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException,
            ServletException {
        ResponseResult result = new ResponseResult(HttpStatus.FORBIDDEN.value(),
                "权限不足");
        String json = JSON.toJSONString(result);
        WebUtils.renderString(response, json);
    }
}