package com.ij026.team3.mfpe.authmicroservice;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class UserDetailsLoaderTest {

	@Autowired
	private UserDetailsLoader userDetailsLoader;

	@BeforeAll
	static void setUpBeforeClass() throws Exception {
	}

	@AfterAll
	static void tearDownAfterClass() throws Exception {
	}

	@BeforeEach
	void setUp() throws Exception {
	}

	@AfterEach
	void tearDown() throws Exception {
	}

	@Test
	void testGetPassword_valid() {
		assertEquals("abcd1234", this.userDetailsLoader.getPassword("subsa"));
	}

	@Test
	void testGetPassword_whenInValid() {
		assertThat(this.userDetailsLoader.getPassword("axax")).isNull();
	}

}
