package be.post.epfadapter.controller;

import be.bpost.epfadapter.EpfAdapterApplication;
import be.bpost.epfadapter.OAuth2ResourceServerSecurityConfiguration;
import be.bpost.epfadapter.controller.ConnectionsController;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@WebMvcTest(ConnectionsController.class)
@ContextConfiguration(classes = {EpfAdapterApplication.class})
@Import(OAuth2ResourceServerSecurityConfiguration.class)
public class ConnectionsControllerTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionsControllerTest.class);

    @Autowired
    MockMvc mockMvc;

    @Test
    void connectionsCanBeReadWithJWTTokenSignedByPrivateKeyAndValidatedByPublicKey() throws Exception {
        LOGGER.info("get Connections with valid Bearer JWT token ");
        this.mockMvc.perform(get("/connections").header("Authorization", "Bearer " + JwtTestHelper.getJwtTokenSignedWithPrivateKey()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.*", hasSize(4)));
    }

    @Test
    void connectionsCanNotBeReadWithoutJWT() throws Exception{
        LOGGER.info("get Connections without valid Bearer JWT token ");
        this.mockMvc.perform(get("/connections")).andExpect(status().isUnauthorized());
    }

    @Test
    void connectionsCanNotBeReadWithWrongJWT() throws Exception{
        LOGGER.info("get Connections with wrong Bearer JWT token ");
        String jwtTokenValid = JwtTestHelper.getJwtTokenSignedWithPrivateKey();
        this.mockMvc.perform(get("/connections").header("Authorization", "Bearer " + jwtTokenValid + "X")).andExpect(status().isUnauthorized());
    }

}
