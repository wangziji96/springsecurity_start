package com.wzj.controller;

import com.wzj.domain.ResponseResult;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @RequestMapping("/hello")
    //@PreAuthorize("hasAnyAuthority('system:dept:list')")  //只能添加一个权限
    //@PreAuthorize("hasAnyAuthority('admin','test','system:dept:list')") //这个可以添加多个权限，用户满足其中一个权限即可访问
    //@PreAuthorize("hasRole('system:dept:list')")
    //@PreAuthorize("hasAnyRole('admin','system:dept:list')")
    @PreAuthorize("@ex.hasAuthority('system:dept:list')")
    public String hello(){
        return "hello";
    }

    @RequestMapping("/testCors")
    public ResponseResult testCors(){
        return new ResponseResult(200,"testCors");
    }

}
