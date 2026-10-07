package demo;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

public class ApiSecurity {
    void configure(HttpSecurity http) throws Exception {
        http.csrf(withDefaults());
    }
}
