package com.melardev.spring.rest.seeds;


import com.github.javafaker.Faker;
import com.melardev.spring.rest.entities.Role;
import com.melardev.spring.rest.entities.Todo;
import com.melardev.spring.rest.entities.User;
import com.melardev.spring.rest.repositories.TodosRepository;
import com.melardev.spring.rest.services.AppUserService;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.util.Collections;
import java.util.Random;
import java.util.stream.LongStream;

@Service
public class DbSeeder implements CommandLineRunner {
    @Autowired
    TodosRepository todosRepository;

    @Autowired
    DataSource dataSource;

    @Autowired
    private AppUserService userService;

    @Autowired
    Environment environment;

    @Override
    public void run(String... args) {
        System.out.printf("[+] We are using the following database connection string : %s\n" +
                "Go ahead into http://localhost:" + environment.getProperty("server.port") + "/api/h2-console and paste that connection string,\nusername=user,password=password, to access" +
                "the h2 database console ;)", ((HikariDataSource) dataSource).getJdbcUrl());
        long todosCount = this.todosRepository.count();
        Faker faker = new Faker(new Random(System.currentTimeMillis()));
        long todosToSeed = 23;
        todosToSeed -= todosCount;
        LongStream.range(0, todosToSeed).forEach(i -> {
            todosRepository.save(
                    new Todo(
                            StringUtils.collectionToDelimitedString(faker.lorem().words(faker.random().nextInt(2, 5)), "\n"),
                            org.apache.commons.lang3.StringUtils.join(faker.lorem().sentences(faker.random().nextInt(1, 3)), "\n"),
                            faker.random().nextBoolean())
            );
        });

        long usersCount = this.userService.count();
        long usersToSeed = 3;
        usersToSeed -= usersCount;
        LongStream.range(0, usersToSeed).forEach(i -> {
            userService.createUser(faker.name().username(), "password");
        });

            // Create an admin
            User adminUser = new User("admin", "password");
            adminUser.setRoles(Collections.singleton(new Role("ROLE_ADMIN")));
            userService.createUser(adminUser);

    }
}
