package com.wzj.filter;

import com.wzj.domain.LoginUser;
import com.wzj.utils.JwtUtil;
import com.wzj.utils.RedisCache;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Objects;

/**
 * @Author wzj
 * @Date 2022/2/23 22:21
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //获取token
        String token = request.getHeader("token");
        if (!StringUtils.hasText(token)){
            //放行
            filterChain.doFilter(request,response);
            //这里写return是为了别的过滤器返回数据后，再这里停止执行，不去执行下面的语句
            return;
        }

        //解析token
        String userid;
        try {
            Claims claims = JwtUtil.parseJWT(token);
            userid = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }

        //从Redis中获取用户信息
        String redisKey = "login:"+userid;
        //我们存入Redis里面的就是一个LoginUser类型的对象，所以取出来的时候直接写成LoginUser对象即可
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if ((Objects.isNull(loginUser))){
            throw new RuntimeException("用户未登录");
        }

        //存入SecurityContextHolder，不然后面的过滤器不认为用户是已经认证的用户
        //TODO 获取权限信息封装到 authenticationToken
        /**
         *在LoginServiceImpl这个类里面我们用过UsernamePasswordAuthenticationToken这个类的构造方法来保存用户从前端发来的用户名和密码，
         * 这里的UsernamePasswordAuthenticationToken使用的是三个参数的构造方法，原因是这个构造方法会将我们查到的用户设置为已认证状态，
         * 后面的过滤器会发现这个标志位是已认证状态。
         * 权限信息还没有，所以是null
         *
         * 个人理解：单纯用JWT就可以验证用户是否登录，这所以要写下面的代码，是为了权限方面的功能。这是查询到的loginUser对象其实已经包含了用户的权限信息
         */
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginUser,null,loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        //放行
        filterChain.doFilter(request,response);
    }
}
