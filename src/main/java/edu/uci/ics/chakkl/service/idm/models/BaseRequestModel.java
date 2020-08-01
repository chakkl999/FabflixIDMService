package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class BaseRequestModel {
    @JsonProperty(value = "email", required = true)
    private String email;

    @JsonCreator
    public BaseRequestModel(@JsonProperty(value = "email", required = true) String email)
    {
        this.email = email;
    }

    @JsonProperty("email")
    public String getEmail()
    {
        return email;
    }
}
