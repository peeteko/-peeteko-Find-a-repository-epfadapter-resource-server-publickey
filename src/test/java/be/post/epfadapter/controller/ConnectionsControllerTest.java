package be.post.epfadapter.controller;

import be.bpost.epfadapter.EpfAdapterApplication;
import be.bpost.epfadapter.OAuth2ResourceServerSecurityConfiguration;
import be.bpost.epfadapter.controller.ConnectionsController;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest(ConnectionsController.class)
@ContextConfiguration(classes = {EpfAdapterApplication.class})
@Import(OAuth2ResourceServerSecurityConfiguration.class)
public class ConnectionsControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void connectionsCanBeReadWithScopeConnectionsReadAuthority() throws Exception {
        this.mockMvc.perform(get("/connections").with(jwt().jwt((jwt) -> jwt.claim("scope", "connections:write connections:read"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.*", hasSize(4)));

        this.mockMvc.perform(get("/connections").with(jwt().authorities(new SimpleGrantedAuthority(("SCOPE_connections:read")))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.*", hasSize(4)));
    }

  /* @Test
    void connectionsCanBeReadWithScopeConnectionsReadAuthority2() throws Exception {
        this.mockMvc.perform(get("/connections").header("Authorization", "Bearer " + getJwtTokenSignedWithPrivateKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.*", hasSize(3)));

    }*/

    @Test
    void connectionsCanNotBeReadWithoutJWT() throws Exception{
        this.mockMvc.perform(get("/connections")).andExpect(status().isUnauthorized());
    }

    @Test
    void connectionsCanNotBeReadWithoutScopeConnectionsRead() throws Exception{
        this.mockMvc.perform(get("/connections").with(jwt())).andExpect(status().isForbidden());
    }


}
