package com.wzj.handler;

import com.alibaba.fastjson.JSON;
import com.wzj.domain.ResponseResult;
import com.wzj.utils.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author wzj
 * @Date 2022/4/3 14:21
 */
@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        //生成返回给前端的json字符串。Spring提供的枚举类HttpStatus.UNAUTHORIZED，401
        ResponseResult result = new ResponseResult(HttpStatus.UNAUTHORIZED.value(),"用户认证失败，请重新登录");
        String json = JSON.toJSONString(result);
        //处理认证异常 WebUtils这个工具类提供了一个设置返回状态码等功能的方法
        WebUtils.renderString(response,json);
    }
}
