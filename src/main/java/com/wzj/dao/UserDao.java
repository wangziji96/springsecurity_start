package com.wzj.dao;

import com.wzj.domain.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/2/18 21:44
 */
@Mapper
public interface UserDao {

    User selectByNameAndPassword(User user);

    List<User> selectAll();

    User selectByUserName(User user);

}
