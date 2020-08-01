package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SessionLogoutRequestModel extends BaseRequestModel{
    @JsonProperty(value = "session_id", required = true)
    private String session_id;

    @JsonCreator
    public SessionLogoutRequestModel(@JsonProperty(value = "email", required = true) String email,
                                     @JsonProperty(value = "session_id", required = true) String session_id)
    {
        super(email);
        this.session_id = session_id;
    }

    @JsonProperty("session_id")
    public String getSession_id()
    {
        return session_id;
    }
}
