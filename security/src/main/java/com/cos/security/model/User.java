package com.cos.security.model;

import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;

import java.sql.Timestamp;

import static javax.persistence.GenerationType.*;
import static lombok.AccessLevel.*;

@Entity
@Getter @Setter
@NoArgsConstructor(access = PROTECTED)
public class User {
    @Id @GeneratedValue(strategy = IDENTITY)
    private Long id;

    private String username;
    private String password;
    private String email;
    private String role;
    private String provider;    //
    private String providerId;

    @CreationTimestamp
    private Timestamp createDate;

//    private Timestamp loginDate;

    @Builder
    public User(String username, String password, String email, String role, String provider, String providerId, Timestamp createDate) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.createDate = createDate;
    }
}
