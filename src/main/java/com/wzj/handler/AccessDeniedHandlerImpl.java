package com.wzj.handler;

import com.alibaba.fastjson.JSON;
import com.wzj.domain.ResponseResult;
import com.wzj.utils.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author wzj
 * @Date 2022/4/3 14:38
 */
@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
        //生成返回给前端的json字符串。Spring提供的枚举类HttpStatus.UNAUTHORIZED，403
        ResponseResult result = new ResponseResult(HttpStatus.FORBIDDEN.value(),"您的权限不足");
        String json = JSON.toJSONString(result);
        //处理授权异常 WebUtils这个工具类提供了一个设置返回状态码等功能的方法
        WebUtils.renderString(response,json);
    }
}
