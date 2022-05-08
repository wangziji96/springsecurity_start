package com.wzj.domain;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @Author wzj
 * @Date 2022/2/19 13:35
 */
@Data
@NoArgsConstructor
public class LoginUser implements UserDetails {

    //存储数据库查到的用户信息
    private User user;

    //存储用户的权限信息
    private List<String> perminssions;

    public LoginUser(User user, List<String> perminssions){
        this.user = user;
        this.perminssions = perminssions;
    }

    //GrantedAuthority是spring里面的类，需要它序列化到Redis里面，不然会报异常
    @JSONField(serialize = false)
    List<GrantedAuthority> authorities;
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities != null){
            return authorities;
        }
        //获取权限信息
        //把perminssions中String类型的权限信息封装成SimpleGrantedAuthority对象
        authorities = new ArrayList<>();
        for (String perminssion : perminssions) {
            SimpleGrantedAuthority authority = new SimpleGrantedAuthority(perminssion);
            authorities.add(authority);
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
        //return null;
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        //return false;
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        //return false;
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        //return false;
        return true;
    }

    @Override
    public boolean isEnabled() {
        //return false;
        return true;
    }
}
