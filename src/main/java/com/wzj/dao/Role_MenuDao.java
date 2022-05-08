package com.wzj.dao;

import com.wzj.domain.Role_Menu;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;


@Mapper
public interface Role_MenuDao {

    //根据角色id查询权限id
    List<Role_Menu> selectMenuIdByRoleId(Long id);

}
