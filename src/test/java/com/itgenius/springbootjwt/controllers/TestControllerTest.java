package com.itgenius.springbootjwt.controllers;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.junit.jupiter.api.Test;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)

public class TestControllerTest {

    @Test
    @GetMapping(value = "/all")
    public void allAccess() {
        // Assert.assertEquals(200, allAccess());
        // return "Public Content";
    }

    @Test
    @GetMapping(value = "/user")
    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MODERATOR','ROLE_ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @Test
    @GetMapping(value = "/mod")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String modAccess() {
        return "Moderator Content.";
    }

    @Test
    @GetMapping(value = "/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String adminAccess() {
        return "Admin Content.";
    }
}
