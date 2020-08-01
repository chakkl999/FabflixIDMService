package edu.uci.ics.chakkl.service.idm.util;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

public class Header {
    private String email, session_id, transaction_id;

    public Header(HttpHeaders headers)
    {
        email = headers.getHeaderString("email");
        session_id = headers.getHeaderString("session_id");
        transaction_id = headers.getHeaderString("transaction_id");
    }

    public String getEmail() {
        return email;
    }

    public String getSession_id() {
        return session_id;
    }

    public String getTransaction_id() {
        return transaction_id;
    }

    public void setHeader(Response.ResponseBuilder builder)
    {
        if(email != null)
            builder.header("email", email);
        if(session_id != null)
            builder.header("session_id", session_id);
        if(transaction_id != null)
            builder.header("transaction_id", transaction_id);
    }
}