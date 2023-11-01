package com.itgenius.springbootjwt.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/test")
public class TestController {
    
    @GetMapping(value = "/all")
    public String allAccess(){
        return "Public Content";
    }

    @GetMapping(value = "/user")
    @PreAuthorize("hasAnyRole('ROLE_USER','ROLE_MODERATOR','ROLE_ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping(value = "/mod")
    @PreAuthorize("hasRole('ROLE_MODERATOR')")
    public String modAccess() {
        return "Moderator Content.";
    }

    @GetMapping(value = "/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String adminAccess() {
        return "Admin Content.";
    }

}
