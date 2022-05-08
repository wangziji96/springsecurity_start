package com.wzj.service.impl;

import com.wzj.dao.User_RoleDao;
import com.wzj.domain.User_Role;
import com.wzj.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 16:50
 */
@Service
public class UserRoleServiceImpl implements UserRoleService {

    @Autowired
    User_RoleDao user_roleDao;

    //获取查询到的角色id
    @Override
    public List<Long> getRoleId(Long id) {
        List<User_Role> user_roles = user_roleDao.selectRoleIdByUid(id);

        //查询到的角色可能有多个，所以用List数组
        List<Long> list = new ArrayList<>();
        //遍历集合，取出查询到的角色id
        for (User_Role user_role:
             user_roles) {
            Long role_id = user_role.getRole_id();
            list.add(role_id);
        }
        return list;
    }
}
