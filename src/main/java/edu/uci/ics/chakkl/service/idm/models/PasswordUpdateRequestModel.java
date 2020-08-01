package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordUpdateRequestModel extends RegisterLoginRequestModel {
    @JsonProperty(value = "session_id", required = true)
    private String session_id;

    @JsonCreator
    public PasswordUpdateRequestModel(@JsonProperty(value = "email", required = true) String email,
                                     @JsonProperty(value = "password", required = true) char[] password,
                                     @JsonProperty(value = "session_id", required = true) String session_id)
    {
        super(email, password);
        this.session_id = session_id;
    }

    @JsonProperty("session_id")
    public String getSession_id()
    {
        return session_id;
    }
}
