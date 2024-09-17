package com.example.securitytest.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.example.securitytest.domain.Menu;


import java.util.List;

/**
 * <p>
 * 菜单权限表 Mapper 接口
 * </p>
 *
 * @author 哈纳桑
 * @since 2024-05-09
 */
public interface MenuMapper extends BaseMapper<Menu> {
    List<String> selectPermsByUserId (Long userId);

}
