package com.yaya.security;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.yaya.entity.SysDepartment;
import com.yaya.entity.SysRole;
import com.yaya.entity.SysRoleDept;
import com.yaya.entity.SysUser;
import com.yaya.entity.SysUserRole;
import com.yaya.mapper.SysDepartmentMapper;
import com.yaya.mapper.SysRoleDeptMapper;
import com.yaya.mapper.SysRoleMapper;
import com.yaya.mapper.SysUserMapper;
import com.yaya.mapper.SysUserRoleMapper;
import jakarta.annotation.Resource;
import org.apache.commons.collections4.CollectionUtils;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 从数据库获取用户信息,将查询的用户信息送给SpringSecurity上下文
 * 用户信息包含: 基本用户信息+用户角色信息+角色权限信息  RBAC模式
 */
@Transactional
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Resource
    private SysUserMapper sysUserMapper;
    @Resource
    private SysRoleMapper sysRoleMapper;
    @Resource
    private SysDepartmentMapper sysDepartmentMapper;
    @Resource
    private SysRoleDeptMapper sysRoleDeptMapper;
    @Resource
    private SysUserRoleMapper sysUserRoleMapper;



    @Override @NullMarked
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        SysUser user = sysUserMapper.selectOne(new LambdaQueryWrapper<SysUser>()
                .eq(SysUser::getUsername, username)
                .eq(SysUser::getIsDeleted, 0)
        );
        if(null==user){
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        //获取部门
        SysDepartment department = sysDepartmentMapper.selectById(user.getDeptId());
        if(Objects.nonNull(department)){
            user.setSysDepartment(department);
        }
        //用户的角色编号列表
        List<String> roleCodeList = new ArrayList<>();
        //角色下的 - 自定义部门权限(多角色的自定义部门取并集)
        List<SysRoleDept> roleDeptList =  new ArrayList<>();
        //获取用户的所有角色关联
        List<SysUserRole> userRoles = sysUserRoleMapper.selectList(new LambdaQueryWrapper<SysUserRole>().eq(SysUserRole::getUserId, user.getUserId()));
        if(CollectionUtils.isNotEmpty(userRoles)){
            List<Long> roleIds = userRoles.stream().map(SysUserRole::getRoleId).toList();
            //获取角色列表(过滤: 未删除且未停用的角色)
            List<SysRole> roles = sysRoleMapper.selectList(new LambdaQueryWrapper<SysRole>()
                    .in(SysRole::getRoleId, roleIds)
                    .eq(SysRole::getIsDeleted, 0)
                    .eq(SysRole::getStatus, 1)
            );
            if(CollectionUtils.isNotEmpty(roles)){
                user.setSysRoles(roles); //设置角色列表
                //添加到角色编号集合中用于授权
                roles.forEach(role -> roleCodeList.add(role.getRoleCode()));
                //所有角色下的自定义部门数据权限(并集)
                List<SysRoleDept> sysRoleDepts = sysRoleDeptMapper.selectList(new LambdaQueryWrapper<SysRoleDept>().in(SysRoleDept::getRoleId, roleIds));
                if(CollectionUtils.isNotEmpty(sysRoleDepts)){
                    roleDeptList.addAll(sysRoleDepts);
                }
            }
        }
        return new LoginUserDetails(user,roleCodeList,roleDeptList);
    }
}
