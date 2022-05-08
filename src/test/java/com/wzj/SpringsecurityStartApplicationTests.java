package com.wzj;

import com.wzj.dao.UserDao;
import com.wzj.domain.User;
import com.wzj.utils.JwtUtil;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootTest
class SpringsecurityStartApplicationTests {

    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void contextLoads() {
        String encode = passwordEncoder.encode("123456");
        System.out.println("加密之后的密码："+encode);

        //$2a$10$WR/XnpdeNWFtapFbpcyEgup/1LbnZL4.hmktQb4TMblLEPp5lQ1lC
        /*boolean matches = passwordEncoder.matches("123456", "$2a$10$WR/XnpdeNWFtapFbpcyEgup/1LbnZL4.hmktQb4TMblLEPp5lQ1lC");
        System.out.println("密码校验结果："+matches);*/
    }

    @Test
    void jwtVerify() throws Exception {
        Claims claims = JwtUtil.parseJWT("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJmM2YwMGEzYTc3Zjk0NTUzOWQ3YTdhNDlmMWZjMmViMiIsInN1YiI6IjEiLCJpc3MiOiJzZyIsImlhdCI6MTY0NTM1MzQ2MiwiZXhwIjoxNjQ1MzU3MDYyfQ.Ju_ec4xR-C2-UcqiMhQywBZDZkHp9Z2AnSbwCXju1Rs");
        String subject = claims.getSubject();
        System.out.println(subject);
    }

}
