package com.wzj.dao;

import com.wzj.dao.UserDao;
import com.wzj.domain.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/2/18 21:57
 */
@SpringBootTest
public class MapperTest {

    @Autowired
    private UserDao userDao;

    @Autowired
    private MenuDao menuDao;

    @Autowired
    private User_RoleDao user_roleDao;

    @Autowired
    private RoleDao roleDao;

    @Autowired
    private Role_MenuDao role_menuDao;

    @Test
    public void testselectMenuIdByRoleId(){
        List<Role_Menu> role_menus = role_menuDao.selectMenuIdByRoleId(1L);
        System.out.println(role_menus);
    }

    @Test
    public void testSelectRoleByRoleId(){
        Role role = roleDao.selectByRoleId(1L);
        System.out.println(role);
    }

    @Test
    public void testSelectRoleIdByUserId(){
        Long id = 1L;
        List<User_Role> user_roles = user_roleDao.selectRoleIdByUid(id);
        System.out.println(user_roles);
    }

    @Test
    public void testSelectPermsByUserId(){

        List<Menu> list = menuDao.selectPermsByRoleId(1L);
        System.out.println(list);
    }

    @Test
    public void testUserMapper(){
        /*if (userDao !=null){
            List<User> users = userDao.selectAll();
            for (User user : users){
                System.out.println(user);
            }

        }else {
            System.out.println("userDao是空对象");
        }*/
        User user = new User();
        user.setUserName("wzj");
        user.setPassword("{noop}123456");
        User userResult = userDao.selectByNameAndPassword(user);
        System.out.println(userResult);
    }

}
