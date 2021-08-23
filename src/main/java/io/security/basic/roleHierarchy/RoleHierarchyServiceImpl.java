package io.security.basic.roleHierarchy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService{
    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Override
    @Transactional
    public String findAllHierarchy(){
        List<RoleHierarchy> roleHierarchyList = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> itr = roleHierarchyList.iterator();
        StringBuilder concatedRoles = new StringBuilder();

        while(itr.hasNext()){
            RoleHierarchy roleHierarchy = itr.next();

            // 부모 > 자식
            // 상위 계층이 있는 권한이라면
            if(roleHierarchy.getParent() != null ){
                concatedRoles.append(roleHierarchy.getParent().getChildName());
                concatedRoles.append(" > ");
                concatedRoles.append(roleHierarchy.getChildName());
                concatedRoles.append("\n");
            }
        }

        return concatedRoles.toString();
    }
}
