package org.example.ss_2022_c13_e1.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "clients")
@Getter
@Setter
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String clientId;
    private String secret;
    private String scope;
    private String authMethod;
    private String grantType;
    private String redirectUri;

}