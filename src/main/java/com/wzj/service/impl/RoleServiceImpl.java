package com.wzj.service.impl;

import com.wzj.dao.RoleDao;
import com.wzj.domain.Role;
import com.wzj.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 17:52
 */
@Service
public class RoleServiceImpl implements RoleService {

    @Autowired
    RoleDao roleDao;

    @Override
    public List<Long> getRoleId(List<Long> ids) {

        List<Long> lists = new ArrayList<>();
        //变量传进来的角色id,查询状态是可用的角色，并获取这些角色的id
        for (Long id:ids
             ) {
            Role role = roleDao.selectByRoleId(id);
            lists.add(role.getId());
        }
        //获取角色id并返回
        return lists;
    }
}
