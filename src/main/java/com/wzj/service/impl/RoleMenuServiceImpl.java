package com.wzj.service.impl;

import com.wzj.dao.Role_MenuDao;
import com.wzj.domain.Role_Menu;
import com.wzj.service.RoleMenuService;
import com.wzj.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 19:48
 */
@Service
public class RoleMenuServiceImpl implements RoleMenuService {

    @Autowired
    private Role_MenuDao role_menuDao;

    @Override
    public List<Long> getMenuIds(List<Long> ids) {

        List<Long> list = new ArrayList<>();

        //根据角色id查询sys_role_menu里的权限id
        for (Long id:ids
             ) {
            List<Role_Menu> role_menus = role_menuDao.selectMenuIdByRoleId(id);
            //遍历获取到的权限id
            for (Role_Menu role_menu:role_menus
                 ) {
                Long menu_id = role_menu.getMenu_id();
                list.add(menu_id);
            }
        }
        return list;
    }


}
