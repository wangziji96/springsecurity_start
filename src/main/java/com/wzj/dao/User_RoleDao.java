package com.wzj.dao;

import com.wzj.domain.User_Role;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 16:06
 */
@Mapper
public interface User_RoleDao {

    //根据用户id查询sys_user_role表的角色id
    List<User_Role> selectRoleIdByUid(Long id);

}
