package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import edu.uci.ics.chakkl.service.idm.util.Result;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginSessionResponseModel extends BaseResponseModel{

    @JsonProperty(value = "session_id")
    private String session_id;

    @JsonCreator
    public LoginSessionResponseModel(Result result,
                                     @JsonProperty(value = "session_id") String session_id)
    {
        super(result);
        this.session_id = session_id;
    }

    @JsonProperty("session_id")
    public String getSession_id()
    {
        return session_id;
    }
}