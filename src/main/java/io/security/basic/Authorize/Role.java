package io.security.basic.Authorize;

import lombok.Data;

import javax.persistence.*;

@Entity
@Data
public class Role {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="role_name")
    private String name;

    @Column(name="role_desc")
    private String desc;

}
