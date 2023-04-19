package be.bpost.epfadapter;


;
import org.springframework.context.annotation.Configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;


import org.springframework.security.web.SecurityFilterChain;

import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;



@EnableWebSecurity
@Configuration
public class OAuth2ResourceServerSecurityConfiguration {

    //TODO: make property file for this
    private static final String SML_HOST_URL = "http://localhost:4200";
    private static final String EPF_MFE_URL = "http://localhost:4201";



    @Bean
    //do not put in production to true this is to see all security details
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(true);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.cors().and()
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.GET, "/connections/**").hasAuthority("SCOPE_connections:read")
                        .requestMatchers(HttpMethod.POST, "/connections/**").hasAuthority("SCOPE_connections:write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer().jwt();


        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins(EPF_MFE_URL, SML_HOST_URL);
            }
        };
    }



}
