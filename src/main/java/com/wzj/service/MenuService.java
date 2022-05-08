package com.wzj.service;

import java.util.List;

/**
 * @Author wzj
 * @Date 2022/3/26 20:29
 */
public interface MenuService {

    List<String> getPermissionKeys(List<Long> lists);

}
