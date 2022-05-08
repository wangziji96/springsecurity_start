package com.wzj.dao;

import com.wzj.domain.Menu;
import com.wzj.domain.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/23 21:17
 */
@Mapper
public interface MenuDao {

    //根据UserId来查询权限的，所以传入的值是User类型的
    List<Menu> selectPermsByRoleId(Long id);

}
