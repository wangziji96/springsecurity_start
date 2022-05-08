package com.wzj.domain;

import lombok.Data;

import java.util.Date;

/**
 * @Author wzj
 * @Date 2022/3/26 17:15
 */
@Data
public class Role {

    Long id;//角色id
    String name;//角色名
    String role_key;//角色权限字符串
    Character status;//角色状态（0正常 1停用）
    Integer del_flag;
    Integer create_by;
    Date create_time;
    Integer update_by;
    Date update_time;
    String remark;

}
