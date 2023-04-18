package be.bpost.epfadapter.domain.dtos;


import be.bpost.epfadapter.common.enums.Language;
import be.bpost.epfadapter.common.enums.PlatformType;
import be.bpost.epfadapter.common.enums.State;

import java.net.URL;
import java.time.Instant;


public class ConnectionDto {
    private Long id;
    private String shopId;
    private PlatformType platformType;
    private Language language;
    private State state;
    private URL shopAdminLink;
    private URL authorizationUrl;
    private Instant createdAt;
    private Instant updatedAt;


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getShopId() {
        return shopId;
    }

    public void setShopId(String shopId) {
        this.shopId = shopId;
    }

    public PlatformType getPlatformType() {
        return platformType;
    }

    public void setPlatformType(PlatformType platformType) {
        this.platformType = platformType;
    }

    public Language getLanguage() {
        return language;
    }

    public void setLanguage(Language language) {
        this.language = language;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public URL getShopAdminLink() {
        return shopAdminLink;
    }

    public void setShopAdminLink(URL shopAdminLink) {
        this.shopAdminLink = shopAdminLink;
    }

    public URL getAuthorizationUrl() {
        return authorizationUrl;
    }

    public void setAuthorizationUrl(URL authorizationUrl) {
        this.authorizationUrl = authorizationUrl;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
