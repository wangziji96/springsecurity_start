package com.wzj.dao;

import com.wzj.domain.Role;
import org.apache.ibatis.annotations.Mapper;

/**
 * @Author wzj
 * @Date 2022/3/26 17:30
 */
@Mapper
public interface RoleDao {

    //根据角色id和角色状态查询角色信息
    Role selectByRoleId(Long id);

}
