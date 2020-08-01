package edu.uci.ics.chakkl.service.idm.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.uci.ics.chakkl.service.idm.IDMService;
import edu.uci.ics.chakkl.service.idm.logger.ServiceLogger;
import edu.uci.ics.chakkl.service.idm.models.LoginSessionResponseModel;
import edu.uci.ics.chakkl.service.idm.models.SessionLogoutRequestModel;
import edu.uci.ics.chakkl.service.idm.security.Session;
import javafx.util.Pair;
import org.glassfish.jersey.jackson.JacksonFeature;

import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;

public class Util {
    public static PreparedStatement preparedStatement(String query, ArrayList<Parameter> parameter) throws SQLException {
        ServiceLogger.LOGGER.info("Preparing statement.");
        PreparedStatement ps = IDMService.getCon().prepareStatement(query);
        int index = 1;
        for(Parameter p: parameter)
            ps.setObject(index++, p.getObject(), p.getType());
        ServiceLogger.LOGGER.info("Finished preparing statement.");
        ServiceLogger.LOGGER.info(ps.toString());
        return ps;
    }

    public static <T> T mapping(String jsonText, Class<T> className)
    {
        if(jsonText == null) {
            ServiceLogger.LOGGER.info("Nothing to map.");
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();

        ServiceLogger.LOGGER.info("Mapping object: " + className.getName());

        try {
            return mapper.readValue(jsonText, className);
        } catch (IOException e) {
            ServiceLogger.LOGGER.info("Mapping Object Failed: " + e.getMessage());
            return null;
        }
    }

    public static int getSession(String email, String session_id)
    {
        String query = "SELECT * FROM session WHERE email = ? AND session_id = ?";
        try {
            PreparedStatement ps = IDMService.getCon().prepareStatement(query);
            ps.setString(1, email);
            ps.setString(2, session_id);
            ResultSet rs = ps.executeQuery();
            if(rs.next()) {
                return rs.getInt("status");
            } else {
                return 5;
            }
        } catch (Exception e) {
            ServiceLogger.LOGGER.info(e.getMessage());
            return 6;
        }
    }

    public static Response internal_server_error()
    {
        Response.ResponseBuilder builder = Response.status(Response.Status.INTERNAL_SERVER_ERROR);
        return builder.build();
    }

}
