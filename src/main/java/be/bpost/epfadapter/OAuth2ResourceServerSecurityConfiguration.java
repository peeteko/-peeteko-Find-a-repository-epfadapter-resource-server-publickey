package be.bpost.epfadapter;


import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;


import org.springframework.security.web.SecurityFilterChain;
@EnableWebSecurity
@Configuration
public class OAuth2ResourceServerSecurityConfiguration {

    @Bean
    //do not put in production to true
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(true);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.GET, "/connections/**").hasAuthority("SCOPE_connections:read")
                        .requestMatchers(HttpMethod.POST, "/connections/**").hasAuthority("SCOPE_connections:write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer().jwt();


        return http.build();
    }


}
