package com.yaya.util;

import com.yaya.entity.SysRole;
import com.yaya.entity.SysRoleDept;
import com.yaya.entity.SysUser;
import com.yaya.exception.GlobalCommonException;
import com.yaya.security.LoginUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Objects;

/**
 * 获取SpringSecurity框架认证后的基本信息
 */
@Slf4j
public class SecurityUtils {

    /**
     * 获取认证信息
     */
    public static Authentication getAuthentication(){
        return SecurityContextHolder.getContext().getAuthentication();
    }

    /**
     * 获取当前登录SpringSecurity用户信息
     */
    public static LoginUserDetails getLoginUser(){
        try {
            Authentication authentication = getAuthentication();
            if(authentication!=null && authentication.isAuthenticated()){
                Object principal = authentication.getPrincipal();
                if(Objects.nonNull(principal)){
                    if(principal instanceof LoginUserDetails){
                        return (LoginUserDetails) principal;
                    }
                }
            }
            return null;
        }catch (Exception e){
            log.error("getLoginUser",e);
            throw new GlobalCommonException("未认证,请重新认证");
        }
    }

    /**
     * 获取当前登录用户信息
     */
    public static SysUser getUser(){
        LoginUserDetails user = getLoginUser();
        if(null!=user){
            return user.getSysUser();
        }
        return null;
    }

    /**
     * 获取当前登录用户的ID
     */
    public static Long getUserId(){
        SysUser user = getUser();
        if(null!=user){
            return user.getUserId();
        }
        return null;
    }

    /**
     * 获取部门ID
     */
    public static Long getDeptId(){
        SysUser user = getUser();
        if(null!=user){
            return user.getDeptId();
        }
        return null;
    }

    /**
     * 角色下的自定义部门数据
     */
    public static List<SysRoleDept> getRoleDept(){
        LoginUserDetails loginUser = getLoginUser();
        if(null!=loginUser){
            return loginUser.getRoleDeptList();
        }
        return List.of();
    }

    /**
     * 获取当前登录用户账号
     */
    public static String getUsername(){
        SysUser user = getUser();
        if(null!=user){
            return user.getUsername();
        }
        return null;
    }

    /**
     * 获取当前用户的角色列表
     */
    public static List<SysRole> getRoles(){
        SysUser user = getUser();
        if(null!=user){
            return user.getSysRoles();
        }
        return List.of();
    }

    /**
     * 获取当前用户的角色编号列表(用户和角色是多对多关系)
     */
    public static List<String> getRoleCodes(){
        LoginUserDetails loginUser = getLoginUser();
        if(null!=loginUser){
            return loginUser.getRoleCodes();
        }
        return List.of();
    }

    /**
     * 获取当前用户的角色ID列表(用户和角色是多对多关系)
     */
    public static List<Long> getRoleIds(){
        List<SysRole> roles = getRoles();
        if(null!=roles && !roles.isEmpty()){
            return roles.stream().map(SysRole::getRoleId).toList();
        }
        return List.of();
    }

    /**
     * 判断当前用户是否拥有指定角色编号的角色(任一角色命中即为true)
     */
    public static Boolean hasRoleCode(String roleCode){
        List<String> roleCodes = getRoleCodes();
        if(null!=roleCodes && !roleCodes.isEmpty() && null!=roleCode){
            for (String code : roleCodes) {
                if(roleCode.equalsIgnoreCase(code)){
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 获取当前用户所有角色中范围最大的数据权限(多角色取最宽: 数值最小)
     * 数据权限(1-所有数据 2-部门及子部门数据 3-本部门数据 4-本人数据 5-自定义部门数据)
     * 注意: 自定义部门(5)的部门数据为所有角色自定义部门的并集,通过 getRoleDept() 获取
     */
    public static Integer getMaxDataScope(){
        List<SysRole> roles = getRoles();
        if(null!=roles && !roles.isEmpty()){
            Integer maxDataScope = null;
            for (SysRole role : roles) {
                Integer dataScope = role.getDataScope();
                if(null!=dataScope && (null==maxDataScope || dataScope < maxDataScope)){
                    maxDataScope = dataScope;
                }
            }
            return maxDataScope;
        }
        return null;
    }

    /**
     * 判断是不是平台超级管理员角色(任一角色命中即为true)
     */
    public static Boolean isRoot(){
        return hasRoleCode("root");
    }

    /**
     * 判断是不是平台系统管理员角色(任一角色命中即为true)
     */
    public static Boolean isAdmin(){
        return hasRoleCode("admin");
    }

    /**
     * 判断是不是平台运营管理员角色(任一角色命中即为true)
     */
    public static Boolean isOperation(){
        return hasRoleCode("operation");
    }

    /**
     * 判断是不是平台所有管理员(任一角色命中即为true)
     */
    public static Boolean isRootOrAdminOrOperation(){
        return isAdmin() || isOperation() || isRoot();
    }
}
