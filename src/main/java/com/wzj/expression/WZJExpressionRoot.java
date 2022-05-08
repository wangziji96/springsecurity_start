package com.wzj.expression;

import com.wzj.domain.LoginUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/4/4 15:21
 */

@Component("ex")//给这个bean起名叫ex
public class WZJExpressionRoot {

    //自定义权限校验方法
    public boolean hasAuthority(String authority){
        //获取当前用户权限
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //在过滤器JwtAuthenticationTokenFilter中，我们添加的就是Loginuser对象，所以这里可以强转成这个类型
        LoginUser loginUser = (LoginUser)authentication.getPrincipal();
        List<String> perminssions = loginUser.getPerminssions();
        //判断用户权限集合中是否存在authority
        return perminssions.contains(authority);
    }

}
