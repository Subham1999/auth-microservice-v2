package com.ij026.team3.mfpe.authmicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
public class AuthMicroserviceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthMicroserviceApplication.class, args);
	}

}
