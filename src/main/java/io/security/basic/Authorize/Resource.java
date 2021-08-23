package io.security.basic.Authorize;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Resource {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    private String resourceName;

    @Column
    private String httpMethod;

    @Column
    private int orderNum;

    @Column
    private String resourceType;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name="role_resources", joinColumns = {@JoinColumn(name="resource_id")},
                                      inverseJoinColumns = {@JoinColumn(name="role_id")})
    private Set<Role> roleSet = new HashSet<>();

}
