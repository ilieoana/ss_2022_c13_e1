# Spring Security Fundamentals - The OAuth2 Authorization Server - Part 3

This project is based on **Lesson 13 - The OAuth2 Authorization Server - Part 3**
the [Spring Security Fundamentals](https://www.youtube.com/playlist?list=PLEocw3gLFc8X_a8hGWGaBnSkPFJmbb8QP) tutorial
series by **Laur Spilca** on
YouTube.

## 📚 Tutorial Reference

- **Author:** Laur Spilca
- **Series:** Spring Security Fundamentals
- **Lesson:** 13 - The OAuth2 Authorization Server - Part 3
- **Link:
  ** [Watch on YouTube](https://www.youtube.com/watch?v=pQtykd2o0Ng&list=PLEocw3gLFc8X_a8hGWGaBnSkPFJmbb8QP&index=15)

## 🛠️ What I Did

This project was implemented as part of my learning journey with Spring Security. I followed the tutorial closely and:

- Recreated the project from scratch in my local environment.
- Set up an OAuth2 Authorization Server using Spring Security 6.
- This lesson involves moving from in-memory users and clients to using ones whose information is saved in the database.
- In achieving this, the following concepts were implemented:
    - JPA Hibernate to create tables according to User and Client entities;
    - Spring Data JPA repositories to provide CRUD operations and custom queries;
    - An implementation of RegisteredClientRepository, CustomClientService, to manage OAuth2 clients, including saving
      and retrieving registered client details;
    - An implementation of UserDetailsService, CustomUserDetailsService, o load application users from the database for
      authentication.
