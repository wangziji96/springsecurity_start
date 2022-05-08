package com.wzj.service.impl;

import com.wzj.dao.UserDao;
import com.wzj.domain.LoginUser;
import com.wzj.domain.User;
import com.wzj.service.MenuService;
import com.wzj.service.RoleMenuService;
import com.wzj.service.RoleService;
import com.wzj.service.UserRoleService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * @Author wzj
 * @Date 2022/2/19 13:20
 */
@Slf4j
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private UserRoleService userRoleService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private RoleMenuService roleMenuService;

    @Autowired
    private MenuService menuService;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {

        log.info("输出来的s是："+s);

        //查询用户信息
        User user = new User();
        user.setUserName(s);
        /*user.setPassword("");*/
        User userResult = userDao.selectByUserName(user);
        if (Objects.isNull(userResult)){
            throw new RuntimeException("用户名或密码错误");
        }else {
            log.info(userResult.toString());
        }
        //TODO 查询对应用户权限信息
        //权限是用字符串记录的，权限有多个，所以这里用List集合
        //List<String> list = new ArrayList<>(Arrays.asList("test","admin"));

        //根据用户id去sys_user_role表查询角色id
        List<Long> roleIds = userRoleService.getRoleId(userResult.getId());

        //根据查询到的角色id去查询角色表，原因是我们要通过这个步骤查询用户id所对应的未停用的角色id
        List<Long> roleStatusId = roleService.getRoleId(roleIds);

        //根据查询到的status=0的角色的id去查询sys_role_menu表，获取权限id
        List<Long> menuIds = roleMenuService.getMenuIds(roleStatusId);

        //根据查询到的权限id，去sys_menu查询权限状态为0（可用）的角色的具体权限
        List<String> permissionKeys = menuService.getPermissionKeys(menuIds);

        //把数据封装成UserDetails,UserDetails封装了用户信息和用户权限信息
        return new LoginUser(userResult,permissionKeys);
    }
}
