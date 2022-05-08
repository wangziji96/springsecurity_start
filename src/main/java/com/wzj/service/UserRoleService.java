package com.wzj.service;

import com.wzj.domain.User_Role;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 16:49
 */
public interface UserRoleService {

    //获取查询到的角色id
    public List<Long> getRoleId(Long id);

}
