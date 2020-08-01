package edu.uci.ics.chakkl.service.idm.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import edu.uci.ics.chakkl.service.idm.util.Header;
import edu.uci.ics.chakkl.service.idm.util.Result;

import javax.ws.rs.core.Response;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class BaseResponseModel {
    @JsonIgnore
    private Response.Status responseCode;
    @JsonProperty(value = "resultCode", required = true)
    private int resultCode;
    @JsonProperty(value = "message", required = true)
    private String message;

    public BaseResponseModel(){
    }

    public BaseResponseModel(Result result) {
        this.responseCode = result.getHttpCode();
        this.resultCode = result.getResultCode();
        this.message = result.getMessage();
    }

    @JsonIgnore
    public void setResult(Result result) {
        this.responseCode = result.getHttpCode();
        this.resultCode = result.getResultCode();
        this.message = result.getMessage();
    }

    @JsonIgnore
    public Response.Status getResult() {
        return responseCode;
    }

    @JsonProperty("resultCode")
    public int getResultCode() {
        return resultCode;
    }

    @JsonProperty("message")
    public String getMessage() {
        return message;
    }

    @JsonIgnore
    public Response buildResponse()
    {
        Response.ResponseBuilder builder;
        if(responseCode == null)
            builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR);
        else
            builder = Response.status(responseCode).entity(this);
        return builder.build();
    }
}