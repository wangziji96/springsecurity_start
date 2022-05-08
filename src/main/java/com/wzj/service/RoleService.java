package com.wzj.service;

import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 17:48
 */
@Service
public interface RoleService {

    //根据查询到的角色id去sys_role_menu表查询权限id
    public List<Long> getRoleId(List<Long> id);

}
