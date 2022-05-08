package com.wzj.service.impl;

import com.wzj.domain.LoginUser;
import com.wzj.domain.ResponseResult;
import com.wzj.domain.User;
import com.wzj.service.LoginService;
import com.wzj.utils.JwtUtil;
import com.wzj.utils.RedisCache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * @Author wzj
 * @Date 2022/2/20 15:13
 */
@Service
public class LoginServiceImpl implements LoginService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
        //AuthenticationManager authenticate对象进行用户认证
        //UsernamePasswordAuthenticationToken的对象是保存前端发来的用户名和密码，作用是和数据库查询到的用户信息作比对
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());
        //会自动调用我们自定义的UserDetailsServiceImpl，然后比对UserDetailsServiceImpl查询到的用户信息，返回Authentication对象
        Authentication  authenticate = authenticationManager.authenticate(authenticationToken);

        //如果认证没通过，给出对应提示
        if (Objects.isNull(authenticate)){
            throw new RuntimeException("登录失败");
        }

        //如果认证通过了，用userid生成jwt
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userid = loginUser.getUser().getId().toString();
        String jwt = JwtUtil.createJWT(userid);
        Map<String,String> map = new HashMap<>();
        map.put("token",jwt);

        //把完整的用户信息存入Redis，userid作为key
        redisCache.setCacheObject("login:"+userid,loginUser);

        return new ResponseResult(200,"登录成功",map);
    }

    @Override
    public ResponseResult logout() {
        //获取SecurityContextHolder中的用户id 将Authentication强转成UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        Long userId = loginUser.getUser().getId();

        //删除Redis中的值
        redisCache.deleteObject("login:"+userId);
        return new ResponseResult(200,"注销成功");
    }
}
