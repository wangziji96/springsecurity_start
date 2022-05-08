package com.wzj.service.impl;

import com.wzj.dao.MenuDao;
import com.wzj.domain.Menu;
import com.wzj.service.MenuService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 20:36
 */
@Service
public class MenuServiceImple implements MenuService {

    @Autowired
    private MenuDao menuDao;
    @Override
    public List<String> getPermissionKeys(List<Long> menuIds) {
        List<String> lists = new ArrayList<>();
        //遍历传进来的权限id集合，获取状态为可用的权限
        for (Long menuid:menuIds
             ) {
            //查询状态为可用的权限对象
            List<Menu> menus = menuDao.selectPermsByRoleId(menuid);
            //获取具体的权限信息
            for (Menu menu:menus
                 ) {
                //获取权限信息并添加到List集合里面
                lists.add(menu.getPerms());
            }
        }
        return lists;
    }
}
