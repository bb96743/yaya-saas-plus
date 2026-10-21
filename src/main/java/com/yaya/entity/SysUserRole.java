package com.yaya.entity;

import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;
import com.github.jeffreyning.mybatisplus.anno.MppMultiId;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.io.Serializable;

/**
 * 用户角色关联表 - sys_user_role
 */
@Data
@TableName(value = "sys_user_role")
public class SysUserRole implements Serializable {
    @Schema(description = "用户ID")
    @MppMultiId
    @TableField(value = "user_id")
    private Long userId;

    @Schema(description = "角色ID")
    @MppMultiId
    @TableField(value = "role_id")
    private Long roleId;
}
