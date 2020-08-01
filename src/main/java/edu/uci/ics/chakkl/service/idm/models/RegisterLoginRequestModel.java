package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class RegisterLoginRequestModel extends BaseRequestModel{
    @JsonProperty(value = "password", required = true)
    private char password[];

    @JsonCreator
    public RegisterLoginRequestModel(@JsonProperty(value = "email", required = true) String email,
                                     @JsonProperty(value = "password", required = true) char[] password)
    {
        super(email);
        this.password = password;
    }

    @JsonProperty("password")
    public char[] getPassword()
    {
        return password;
    }
}
