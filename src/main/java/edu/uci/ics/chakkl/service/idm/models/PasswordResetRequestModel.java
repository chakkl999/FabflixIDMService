package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordResetRequestModel extends RegisterLoginRequestModel {
    @JsonProperty(value = "reset_token", required = true)
    private String reset_token;

    @JsonCreator
    public PasswordResetRequestModel(@JsonProperty(value = "email", required = true) String email,
                                      @JsonProperty(value = "password", required = true) char[] password,
                                      @JsonProperty(value = "reset_token", required = true) String reset_token)
    {
        super(email, password);
        this.reset_token = reset_token;
    }

    @JsonProperty("reset_token")
    public String getReset_token() {
        return reset_token;
    }
}
