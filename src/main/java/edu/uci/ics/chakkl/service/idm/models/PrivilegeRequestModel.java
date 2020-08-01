package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class PrivilegeRequestModel extends BaseRequestModel{

    @JsonProperty(value = "plevel", required = true)
    private int plevel;

    @JsonCreator
    public PrivilegeRequestModel(@JsonProperty(value = "email", required = true) String email,
                                 @JsonProperty(value = "plevel", required = true) int plevel)
    {
        super(email);
        this.plevel = plevel;
    }

    @JsonProperty("plevel")
    public int getPlevel()
    {
        return plevel;
    }
}
