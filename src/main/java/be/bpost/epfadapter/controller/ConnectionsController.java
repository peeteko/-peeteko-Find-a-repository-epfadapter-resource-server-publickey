package be.bpost.epfadapter.controller;

import be.bpost.epfadapter.common.enums.Language;
import be.bpost.epfadapter.common.enums.State;
import be.bpost.epfadapter.domain.dtos.ConnectionDto;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@RestController
public class ConnectionsController {


    @GetMapping("/connections")
    public ResponseEntity<List<ConnectionDto>> getAll(@AuthenticationPrincipal Jwt jwt) {


        List<ConnectionDto> connections = new ArrayList<>();
        connections.add(getConnectionDto(1L, "autobahn.shopify", Language.DE, State.ESTABLISHED));
        connections.add(getConnectionDto(2L, "fietsen.shopify", Language.NL, State.ESTABLISHED));
        connections.add(getConnectionDto(3L, "voitures.shopify", Language.FR, State.ATTEMPTED));
        connections.add(getConnectionDto(3L, "cars.shopify", Language.EN, State.ATTEMPTED));
        return ResponseEntity.ok(connections);
    }

    private static ConnectionDto getConnectionDto(Long id, String shopId, Language language, State state ) {
        ConnectionDto connectionDto1 = new ConnectionDto();
        connectionDto1.setId(id);
        connectionDto1.setShopId(shopId);
        connectionDto1.setLanguage(language);
        connectionDto1.setState(state);
        try {
            connectionDto1.setShopAdminLink(URI.create("https://"+shopId+"/admin").toURL());
            connectionDto1.setAuthorizationUrl(URI.create("https://"+shopId+"/authorize").toURL());
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
        connectionDto1.setCreatedAt(Instant.now());
        connectionDto1.setUpdatedAt(Instant.now());
        return connectionDto1;
    }

}
