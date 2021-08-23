package io.security.basic.roleHierarchy;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy,Long> {
    RoleHierarchy findByChildName(String roleName);
}
